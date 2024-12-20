from flask import Flask

def create_app():
    app = Flask(__name__,template_folder="templates")

    from .views import app_blueprint
    app.register_blueprint(app_blueprint)

    return app
