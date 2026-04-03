from dotenv import load_dotenv
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
import os


def main() -> None:
    load_dotenv(".env")

    api_id = int(os.getenv("TELEGRAM_API_ID", "0"))
    api_hash = os.getenv("TELEGRAM_API_HASH", "")

    if not api_id or not api_hash:
        raise RuntimeError("TELEGRAM_API_ID or TELEGRAM_API_HASH is missing in .env")

    # Run interactively so Telethon can prompt for phone, code, and 2FA if needed.
    with TelegramClient(StringSession(), api_id, api_hash) as client:
        print("TELEGRAM_SESSION_STRING=" + client.session.save())


if __name__ == "__main__":
    main()
