LOG_BUFFER = []

def add_log(message):
    LOG_BUFFER.append(message)

    if len(LOG_BUFFER) > 100:
        LOG_BUFFER.pop(0)

def get_logs():
    return LOG_BUFFER