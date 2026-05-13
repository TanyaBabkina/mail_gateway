import asyncio
import yaml
from loguru import logger
from fastapi import FastAPI
import uvicorn
from .smtp_handler import SessionManager
from .antispam_engine import AntispamEngine
from .file_analyzer import FileAnalyzer
from .policy_orchestrator import PolicyOrchestrator
from .models import EmailContext, FileContext, PolicyGroup
from .web_api import app as api_app
import redis, os

def load_config(path: str = "config/settings.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

async def process_email(email: EmailContext, config: dict):
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    session_mgr = SessionManager(redis_url)
    
    # 1. Сессионный анализ + greylisting
    if not session_mgr.handle_rcpt_to(email.session, email.rcpt_to, config["gateway"]):
        email.verdict = "450 Greylisted"
        return email

    # 2. Оркестратор политик
    groups = [PolicyGroup(name="default")]
    orchestrator = PolicyOrchestrator(groups)
    
    # 3. Антиспам
    antispam = AntispamEngine(config["antispam"], orchestrator)
    blocked, reason = antispam.analyze(email)
    if blocked:
        email.verdict = f"BLOCKED: {reason}"
        return email

    # 4. Анализ вложений (пример)
    if email.attachments:
        # stub rule
        rules = [] 
        file_analyzer = FileAnalyzer(rules, config["file_analysis"])
        # run per attachment...

    email.verdict = "ACCEPTED"
    return email

# Запуск API + имитация SMTP-обработчика
if __name__ == "__main__":
    cfg = load_config()
    logger.info("Starting mail-gateway Gateway...")
    uvicorn.run("src.web_api:app", host="0.0.0.0", port=8000)