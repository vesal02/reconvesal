from flask import Flask, render_template, request
from reconpie import run_reconpie

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        domain = request.form['domain']
        results = run_reconpie(domain)
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
