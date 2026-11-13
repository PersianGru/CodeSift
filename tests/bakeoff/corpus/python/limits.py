DEFAULT_LIMITS = "{'max_users': 100, 'max_projects': 20}"


def default_limits() -> dict:
    return eval(DEFAULT_LIMITS)
