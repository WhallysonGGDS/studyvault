"""
Armazenamento das imagens anexadas.

- Local: pasta instance/uploads (fora de /static, então nada fica público).
- Produção: Supabase Storage (plano gratuito), em um bucket privado.
  As imagens são entregues por URLs assinadas de curta duração, sempre
  depois de o app conferir que a nota pertence a quem está pedindo.
"""
import os

from flask import redirect, send_from_directory

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "studyvault")

CONTENT_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
}


class LocalStorage:
    def __init__(self, folder: str):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)

    def save(self, file, name: str):
        path = os.path.join(self.folder, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file.save(path)

    def delete(self, name: str):
        try:
            os.remove(os.path.join(self.folder, name))
        except FileNotFoundError:
            pass

    def serve(self, name: str):
        return send_from_directory(self.folder, name, max_age=3600)


class SupabaseStorage:
    def __init__(self, url: str, key: str, bucket: str):
        import requests

        self.base = f"{url}/storage/v1"
        self.bucket = bucket
        self.http = requests.Session()
        self.http.headers.update({"Authorization": f"Bearer {key}", "apikey": key})
        self._ensure_bucket()

    def _ensure_bucket(self):
        r = self.http.post(
            f"{self.base}/bucket",
            json={"id": self.bucket, "name": self.bucket, "public": False},
            timeout=10,
        )
        # 200 = criado; 400/409 = já existe
        if r.status_code not in (200, 400, 409):
            r.raise_for_status()

    def save(self, file, name: str):
        ext = name.rsplit(".", 1)[-1].lower()
        r = self.http.post(
            f"{self.base}/object/{self.bucket}/{name}",
            data=file.stream.read(),
            headers={"Content-Type": CONTENT_TYPES.get(ext, "application/octet-stream")},
            timeout=30,
        )
        r.raise_for_status()

    def delete(self, name: str):
        self.http.delete(f"{self.base}/object/{self.bucket}/{name}", timeout=10)

    def serve(self, name: str):
        r = self.http.post(
            f"{self.base}/object/sign/{self.bucket}/{name}",
            json={"expiresIn": 3600},
            timeout=10,
        )
        r.raise_for_status()
        return redirect(f"{self.base}{r.json()['signedURL']}")


def make_storage(local_folder: str):
    if SUPABASE_URL and SUPABASE_SERVICE_KEY:
        return SupabaseStorage(SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET)
    return LocalStorage(local_folder)
