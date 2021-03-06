from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/')
def home():
    person = 'guest'
    if request.args.get('name'):
        person = request.args.get('name')
    template = '<h2>Hello %s!</h2>' % person
    return render_template_string(template)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
