import sys, os
import json
import logging
import logging.handlers


def setup_logger(level):
    logger = logging.getLogger('alert_truesight')
    logger.propagate = False

    file_handler = logging.handlers.RotatingFileHandler(
        '/Users/thilinamad/Desktop/splunk_enterprise/splunk' + '/var/log/splunk/alert_truesight.log', 
        maxBytes=25000000, 
        backupCount=5
    )
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.setLevel(level)
    
    return logger
 
logger = setup_logger(logging.DEBUG)

def alert_truesight(settings, hostname, ip_address, object_class_name, object_name, parameter, severity):
    logger.debug(settings)
    logger.info(f'hostname: {hostname}, ip: {ip_address}, object_class: {object_class_name}, object: {object_name},' 
        + f'parameter: {parameter}, severity: {severity}')
    return True


def __get_config(config, key):
    value = config.get(key)
    return '' if not value else value.strip()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("FATAL Unsupported execution mode (expected --execute flag)\n")
        sys.exit(1)
    try:
        settings = json.loads(sys.stdin.read())
        config = settings['configuration']
        success = alert_truesight(
            settings,
            hostname=__get_config(config, 'hostname'),
            ip_address=__get_config(config, 'ip'),
            object_class_name=__get_config(config, 'object_class'),
            object_name=__get_config(config, 'object'),
            parameter=__get_config(config, 'parameter'),
            severity=__get_config(config, 'severity')
        )
        if not success:
            sys.exit(2)
    except Exception as e:
        sys.stderr.write("ERROR Unexpected error: %s\n" % e)
        sys.exit(3)
