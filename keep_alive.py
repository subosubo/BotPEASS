#from threading import Thread
from flask import Flask

app = Flask(__name__)

@app.route('/', methods = ['HEAD','GET'])
async def home():
    #if request.method == 'HEAD':
    #    await botpeas.main()
        
    return 'Stayin Alive'

def keep_alive():
    from waitress import serve
    serve(app, host = "0.0.0.0", port=5000, clear_untrusted_proxy_headers = False)


if __name__ == "__main__":
    keep_alive()