from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "SERVEUR TEST OK!"

@app.route('/test')
def ping():
    return "TEST REUSSI!"

if __name__ == '__main__':
    print("Serveur test sur http://localhost:8000")
    app.run(host='127.0.0.1', port=8000, debug=True)
