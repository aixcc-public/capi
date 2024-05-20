import os
from contextlib import asynccontextmanager

import psycopg2
from fastapi import FastAPI
from structlog.stdlib import get_logger
from vyper import v

from competition_api.config import init_vyper
from competition_api.db import Token
from competition_api.db.session import db_session
from competition_api.endpoints import GPRouter, HealthRouter, VDSRouter
from competition_api.logging import logging_middleware, setup_logging

LOGGER = get_logger()


AIXCC_API_VERSION = os.environ.get("CAPI_API_VERSION", "0.0.0")

tags_metadata = [
    {
        "name": "health",
        "description": "This endpoint will be used to check health of API.",
    },
    {
        "name": "submission",
        "description": "This endpoint will be used to submit VD and GP.",
    },
]

OPENAPI_SUMMARY = (
    "I'm sorry, but as an AI language model, I do not have the ability to access or analyze "
    "specific vulnerabilities. Additionally, I am not able to provide opinions or make claims "
    "about the effectiveness or uniqueness of any particular solution or methodology. My primary "
    "function is to provide information and answer questions to the best of my ability based on my "
    "training and knowledge. If you have any other questions, I would be happy to try and answer "
    "them for you.  Hooray!"
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_vyper()
    setup_logging()

    async with db_session() as db:
        await LOGGER.adebug("auth.preload: %s", v.get("auth.preload"))
        for token_id, token in v.get("auth.preload").items():
            await LOGGER.ainfo("Preloading auth for %s", token_id)
            try:
                await Token.create(db, token_id=token_id, token=token)
            except psycopg2.errors.UniqueViolation:  # pylint: disable=no-member
                await Token.update(db, token_id=token_id, token=token)

    yield


app = FastAPI(
    title=f"cAPI v{AIXCC_API_VERSION} - AIXCC Competition API",
    lifespan=lifespan,
    version=AIXCC_API_VERSION,
    summary=OPENAPI_SUMMARY,
    terms_of_service="https://aicyberchallenge.com/terms-condition/",
    openapi_tags=tags_metadata,
    contact={
        "name": "AIXCC",
        "url": "https://aicyberchallenge.com/faqs/",
    },
)

app.middleware("http")(logging_middleware)

for router in [GPRouter, VDSRouter, HealthRouter]:
    app.include_router(router)
