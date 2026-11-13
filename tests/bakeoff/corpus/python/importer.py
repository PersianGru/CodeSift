import yaml

from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return {"keys": sorted(config)}
