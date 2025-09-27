try:
    from app import app
    print('Import OK')
    print('Routes:', [str(rule) for rule in app.url_map.iter_rules()])
except Exception as e:
    print('ERREUR:', e)
    import traceback
    traceback.print_exc()

import logging
logging.basicConfig(level=logging.DEBUG)
from app import app
app.run(host='0.0.0.0', port=8000, debug=True)