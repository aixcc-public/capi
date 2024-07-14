from structlog.stdlib import get_logger
from vyper import v

LOGGER = get_logger(__name__)


def generate_config():
    url = (
        f"{v.get('database.username')}:"
        f"{v.get('database.password')}@"
        f"{v.get('database.host')}:{v.get('database.port')}/"
        f"{v.get('database.name')}"
    )
    v.set("database.url", f"postgresql+asyncpg://{url}")
    v.set("database.synchronous_url", f"postgresql+psycopg2://{url}")
    v.set(
        "redis.kwargs",
        {
            "host": v.get("redis.host"),
            "port": v.get_int("redis.port"),
            "password": v.get("redis.password"),
            "ssl": v.get_bool("redis.ssl"),
        },
    )


def init_vyper():
    v.set_env_prefix("AIXCC")
    v.automatic_env()

    v.set_config_type("yaml")
    v.set_config_name("config")
    v.add_config_path("/etc/capi/")
    try:
        v.read_in_config()
    except FileNotFoundError:
        LOGGER.warning("Config file not found")

    v.set_default("scoring.reject_duplicate_vds", True)
    v.set_default("run_id", "00000000-0000-0000-0000-000000000000")

    v.set_default("redis.host", "127.0.0.1")
    v.set_default("redis.port", 6379)
    v.set_default("redis.ssl", False)

    v.set_default("redis.channels.audit", "channel:audit")
    v.set_default("redis.channels.results", "channel:results")
    v.set_default("workers", [])
    v.set_default("auth.admins", [])

    generate_config()
