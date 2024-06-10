import os
from contextlib import asynccontextmanager

import sqlalchemy
from fastapi import FastAPI
from structlog.stdlib import get_logger
from vyper import v

from competition_api.config import init_vyper
from competition_api.cp_registry import CPRegistry
from competition_api.db import Token
from competition_api.db.session import db_session
from competition_api.endpoints import GPRouter, HealthRouter, VDSRouter
from competition_api.logging import logging_middleware, setup_logging

LOGGER = get_logger()


AIXCC_API_VERSION = os.environ.get("AIXCC_API_VERSION", "0.0.0")

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_vyper()
    setup_logging()

    if not v.get_bool("mock_mode"):
        # initialize cp registry
        CPRegistry.instance()

        await LOGGER.adebug("auth.preload: %s", v.get("auth.preload"))
        for token_id, token in v.get("auth.preload").items():
            await LOGGER.ainfo("Preloading auth for %s", token_id)
            try:
                async with db_session() as db:
                    await Token.create(db, token_id=token_id, token=token)
            except sqlalchemy.exc.IntegrityError:
                async with db_session() as db:
                    await Token.update(db, token_id=token_id, token=token)

    yield


app = FastAPI(
    title=f"cAPI v{AIXCC_API_VERSION} - AIXCC Competition API",
    lifespan=lifespan,
    version=AIXCC_API_VERSION,
    description="""
# AIxCC Competition API

## API Limitations

* Submitted POV binary input blobs must be 2MiB or smaller, before base64.
* Submitted patch files must be 100KiB or smaller, before base64.
* Submitted patch files may only modify .c, .h, .in, and .java files.
""",
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
