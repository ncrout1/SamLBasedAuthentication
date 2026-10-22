from flask import Flask, request, redirect, session, make_response, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os, json
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'saml_nameid' not in session:
            return redirect(url_for('saml_login'))
        return f(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_SECURE'] = True


@app.before_request
def enforce_https():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)


def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.script_root or '',
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


def init_saml_auth(req):
    with open("settings.json", "r") as f:
        saml_settings = json.load(f)
    settings_obj = OneLogin_Saml2_Settings(settings=saml_settings)
    return OneLogin_Saml2_Auth(req, old_settings=settings_obj)


@app.route('/')
def index():
    return '<a href="/saml/login">Login with Entra ID (SAML)</a>'


@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())


@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    print('SAML errors:', errors)
    print('Last error reason:', auth.get_last_error_reason())
    if not errors:
        session['saml_user_data'] = auth.get_attributes()
        session['saml_nameid'] = auth.get_nameid()
        return f"✅ Logged in as: {session['saml_nameid']}<br><br>Attributes:<br>{session['saml_user_data']}"
    else:
        return f"❌ SAML Error: {errors}<br>Reason: {auth.get_last_error_reason()}"


@app.route('/welcome')
@login_required
def welcome():
    return "<h1>Maza agya 😎</h1>"


@app.route('/metadata')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    metadata = auth.get_settings().get_sp_metadata()
    return make_response(metadata, 200, {'Content-Type': 'text/xml'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
