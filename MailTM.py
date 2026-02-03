# mailjs.py
from __future__ import annotations

import json
import time
import threading
import random
import string
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

import requests


@dataclass
class Result:
    status: bool
    status_code: int
    message: str
    data: Any


MessageCallback = Callable[[Dict[str, Any]], None]
EmptyCallback = Callable[[], None]
ErrorCallback = Callable[[Any], None]
OpenCallback = Callable[[], None]


class Mailjs:
    """
    Port Python de la classe JS Mailjs (https://api.mail.tm).
    - Renvoie des objets Result {status, status_code, message, data}
    - Gère la limite de débit (HTTP 429) avec retry
    - Écoute des événements Mercure (arrive/seen/delete/error/open) sur un thread
    """

    def __init__(self, rate_limit_retries: int = 40, pi_proxie: str = "") -> None:
        self.base_url = "https://api.mail.tm"
        self.base_mercure = "https://mercure.mail.tm/.well-known/mercure"
        self._session = requests.Session()
        self._session.headers.update({"accept": "application/json"})
        self._session.proxies = {
            "http": f"http://{pi_proxie}",
            "https": f"http://{pi_proxie}",
        } if pi_proxie else {}

        self._listener_thread: Optional[threading.Thread] = None
        self._listener_stop = threading.Event()

        # Callbacks (renseignés par .on)
        self._events: Dict[str, Callable] = {}

        self.token: str = ""
        self.id: str = ""
        self.address: str = ""
        self.rate_limit_retries = rate_limit_retries

    # ------------------------
    # Account
    # ------------------------

    def register(self, address: str, password: str) -> Result:
        data = {"address": address, "password": password}
        return self._send("/accounts", "POST", data)

    def login(self, address: str, password: str) -> Result:
        data = {"address": address, "password": password}
        res = self._send("/token", "POST", data)
        if res.status:
            self.token = res.data.get("token", "")
            self.id = res.data.get("id", "")
            self.address = address
            self._session.headers.update({"authorization": f"Bearer {self.token}"})
        return res

    def login_with_token(self, token: str) -> Result:
        self.token = token
        self._session.headers.update({"authorization": f"Bearer {self.token}"})
        res = self.me()
        if not res.status:
            return res
        self.id = res.data.get("id", "")
        self.address = res.data.get("address", "")
        return res

    def me(self) -> Result:
        return self._send("/me")

    def get_account(self, account_id: str) -> Result:
        return self._send(f"/accounts/{account_id}")

    def delete_account(self, account_id: str) -> Result:
        del_res = self._send(f"/accounts/{account_id}", "DELETE")
        if del_res.status:
            self.off()
            self.token = ""
            self.id = ""
            self.address = ""
            self._events = {}
            # Nettoie l'entête d'auth éventuellement présent
            self._session.headers.pop("authorization", None)
        return del_res

    def delete_me(self) -> Result:
        return self.delete_account(self.id)

    # ------------------------
    # Domain
    # ------------------------

    def get_domains(self) -> Result:
        return self._send("/domains")

    def get_domain(self, domain_id: str) -> Result:
        return self._send(f"/domains/{domain_id}")

    # ------------------------
    # Message
    # ------------------------

    def get_messages(self, page: int = 1) -> Result:
        return self._send(f"/messages?page={page}")

    def get_message(self, message_id: str) -> Result:
        return self._send(f"/messages/{message_id}")

    def delete_message(self, message_id: str) -> Result:
        return self._send(f"/messages/{message_id}", "DELETE")

    def set_message_seen(self, message_id: str, seen: bool = True) -> Result:
        return self._send(f"/messages/{message_id}", "PATCH", {"seen": seen})

    # ------------------------
    # Source
    # ------------------------

    def get_source(self, source_id: str) -> Result:
        return self._send(f"/sources/{source_id}")

    # ------------------------
    # Events (SSE Mercure)
    # ------------------------

    def on(
        self,
        event: str,
        callback: Callable[..., None],
    ) -> None:
        """
        event ∈ {"seen", "delete", "arrive", "error", "open"}
        callback: fonction appelée selon l'événement
        """
        if event not in {"seen", "delete", "arrive", "error", "open"}:
            print("Unknown event name:", event)
            return

        # Enregistre le callback
        self._events[event] = callback

        # Démarre l’écoute si nécessaire
        if self._listener_thread is None and event in {"seen", "delete", "arrive", "error", "open"}:
            if not self.id or not self.token:
                print("You must be logged in before starting the event listener.")
                return
            self._start_listener_thread()

    def off(self) -> None:
        """Stoppe proprement l’écoute et efface les callbacks."""
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_stop.set()
            self._listener_thread.join(timeout=5)
        self._listener_thread = None
        self._listener_stop.clear()
        self._events = {}

    # ------------------------
    # Helper
    # ------------------------

    def create_one_account(self) -> Result:
        # 1) Domaine
        domain_res = self.get_domains()
        if not domain_res.status or not domain_res.data:
            return domain_res
        domain = domain_res.data[0].get("domain")

        # 2) Identifiants
        username = f"{self._make_hash(5)}@{domain}"
        password = self._make_hash(8)

        reg_res = self.register(username, password)
        if not reg_res.status:
            return reg_res

        login_res = self.login(username, password)
        if not login_res.status:
            return login_res

        return Result(
            status=True,
            status_code=login_res.status_code,
            message="ok",
            data={"username": username, "password": password},
        )

    # ------------------------
    # Privé
    # ------------------------

    def _make_hash(self, size: int) -> str:
        # proche de l’implémentation JS (alphabet simple)
        alphabet = string.ascii_lowercase + string.digits
        rng = random.SystemRandom()
        return "".join(rng.choice(alphabet) for _ in range(size))

    def _send(
        self,
        path: str,
        method: str = "GET",
        body: Optional[Dict[str, Any]] = None,
        retry: int = 0,
    ) -> Result:
        url = f"{self.base_url}{path}"
        headers = {}

        if method in ("POST", "PATCH"):
            if method == "PATCH":
                headers["content-type"] = "application/merge-patch+json"
            else:
                headers["content-type"] = "application/json"

        try:
            resp = self._session.request(
                method=method,
                url=url,
                headers=headers,
                data=json.dumps(body) if body is not None else None,
                timeout=30,
            )
        except requests.RequestException as e:
            return Result(False, 0, str(e), None)

        # Gestion rate limit 429
        if resp.status_code == 429 and retry < self.rate_limit_retries:
            time.sleep(1)
            return self._send(path, method, body, retry + 1)

        # Choix parseur
        content_type = resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            try:
                data = resp.json()
            except ValueError:
                data = resp.text
        else:
            data = resp.text

        message = "ok" if resp.ok else (data.get("message") if isinstance(data, dict) and "message" in data else data if isinstance(data, str) else data)
        if not message and isinstance(data, dict) and "detail" in data:
            message = data["detail"]

        return Result(resp.ok, resp.status_code, message or "", data)

    # ------ SSE listening ------

    def _start_listener_thread(self) -> None:
        self._listener_stop.clear()
        self._listener_thread = threading.Thread(target=self._listen_sse, name="MailTM-SSE", daemon=True)
        self._listener_thread.start()

    def _listen_sse(self) -> None:
        """
        Implémentation minimaliste de l’EventSource côté Python.
        On lit le flux 'text/event-stream' et on agrège les lignes jusqu’à une ligne vide.
        """
        params = {"topic": f"/accounts/{self.id}"}
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Authorization": f"Bearer {self.token}",
            # User-Agent pour éviter des refus éventuels
            "User-Agent": "mailjs-python/1.0",
        }

        try:
            with self._session.get(self.base_mercure, headers=headers, params=params, stream=True, timeout=60) as r:
                # Événement "open" une fois la connexion établie
                if r.status_code == 200 and "open" in self._events:
                    try:
                        self._events["open"]()  # type: ignore
                    except Exception:
                        pass

                r.raise_for_status()

                buffer_event: Dict[str, str] = {}

                for raw_line in r.iter_lines(decode_unicode=True):
                    if self._listener_stop.is_set():
                        break
                    if raw_line is None:
                        continue

                    line = raw_line.strip()

                    # Fin d’événement (ligne vide)
                    if not line:
                        self._handle_sse_event(buffer_event)
                        buffer_event = {}
                        continue

                    # Champs SSE: "event:", "data:", "id:", etc.
                    if ":" in line:
                        field, value = line.split(":", 1)
                        value = value.lstrip()  # retire l'espace après ':'
                        prev = buffer_event.get(field, "")
                        buffer_event[field] = f"{prev}\n{value}".strip() if prev else value
                    else:
                        # Ligne sans ':' -> on ignore
                        pass

        except Exception as err:
            cb = self._events.get("error")
            if cb:
                try:
                    cb(err)
                except Exception:
                    pass

    def _handle_sse_event(self, event: Dict[str, str]) -> None:
        """
        Détermine le type d’événement ('arrive'|'seen'|'delete') en reproduisant la logique JS.
        Si le serveur envoie un '2' au lieu d’un objet JSON, on va chercher le dernier message.
        """
        data_str = event.get("data")
        if not data_str:
            return

        cb_error = self._events.get("error")
        cb_arrive = self._events.get("arrive")
        cb_seen = self._events.get("seen")
        cb_delete = self._events.get("delete")

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            # données non JSON -> on ignore
            return

        # Ignore les détails de compte
        if isinstance(data, dict) and data.get("@type") == "Account":
            return

        event_type = "arrive"
        if isinstance(data, dict):
            if data.get("isDeleted"):
                event_type = "delete"
            elif data.get("seen"):
                event_type = "seen"

        # Cas spécial: si arrive mais pas d'objet (@type manquant),
        # on tente de récupérer le dernier message via l’API (issues #23,#24 dans le projet d’origine)
        if event_type == "arrive" and (not isinstance(data, dict) or "@type" not in data):
            list_res = self.get_messages()
            if not list_res.status:
                if cb_error:
                    try:
                        cb_error(list_res.message)
                    except Exception:
                        pass
                return
            # Prend le premier élément (dernier reçu)
            if isinstance(list_res.data, list) and list_res.data:
                data = list_res.data[0]

        # Dispatch
        try:
            if event_type == "delete" and cb_delete:
                cb_delete(data)  # type: ignore
            elif event_type == "seen" and cb_seen:
                cb_seen(data)  # type: ignore
            elif event_type == "arrive" and cb_arrive:
                cb_arrive(data)  # type: ignore
        except Exception:
            # ne laisse pas tomber le thread si le callback lève
            pass


# --- Petit exemple d’utilisation ---
if __name__ == "__main__":
    client = Mailjs()

    client.create_one_account()
    print(f"Adresse: {client.address}, ID: {client.id}, Token: {client.token}")

    # Exemple écoute (après login)
    def on_open():
        print("SSE ouvert ✅")

    def on_arrive(msg):
        print("Message arrivé:", msg.get("id"))

    def on_seen(msg):
        print("Message vu:", msg.get("id"))

    def on_delete(msg):
        print("Message supprimé:", msg.get("id"))

    def on_error(err):
        print("SSE erreur:", err)

    # client.login("adresse@domain", "password")
    # client.on("open", on_open)
    # client.on("arrive", on_arrive)
    # client.on("seen", on_seen)
    # client.on("delete", on_delete)
    # client.on("error", on_error)
    # time.sleep(60)
    # client.off()
