from structlog.stdlib import get_logger
from vyper import v

LOGGER = get_logger(__name__)


def generate_config():
    v.set(
        "database.dsn",
        (
            f"dbname={v.get('database.name')} user={v.get('database.username')} "
            f"password={v.get('database.password')} host={v.get('database.host')} "
            f"port={v.get('database.port')}"
        ),
    )
    v.set(
        "database.url",
        (
            f"postgresql+psycopg2://{v.get('database.username')}:"
            f"{v.get('database.password')}@"
            f"{v.get('database.host')}:{v.get('database.port')}/"
            f"{v.get('database.name')}"
        ),
    )


def init_vyper():
    v.set_env_prefix("CAPI")
    v.automatic_env()

    v.set_config_type("yaml")
    v.set_config_name("config")
    v.add_config_path("/etc/capi/")
    try:
        v.read_in_config()
    except FileNotFoundError:
        LOGGER.warning("Config file not found")

    generate_config()
