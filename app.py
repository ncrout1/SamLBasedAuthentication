from flask import Flask, request, redirect, session, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os,json
from flask import Flask, request, redirect, url_for
from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'saml_nameid' not in session:
            return redirect(url_for('saml_login'))
        return f(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
app.secret_key = os.urandom(24)

def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

# def init_saml_auth(req):
#     base_path = os.path.join(os.path.dirname(__file__), 'saml')
#     return OneLogin_Saml2_Auth(req, custom_base_path=base_path)
# def init_saml_auth(req):
#     base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'saml'))
#     return OneLogin_Saml2_Auth(req, custom_base_path=base_path)
def init_saml_auth(req):
    # Load settings.json manually
    with open("settings.json", "r") as f:
        saml_settings = json.load(f)

    # Create SAML settings object
    settings_obj = OneLogin_Saml2_Settings(settings=saml_settings)

    # Create auth object using loaded settings
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
    print(errors)
    if not errors:
        session['saml_user_data'] = auth.get_attributes()
        session['saml_nameid'] = auth.get_nameid()
        return f"✅ Logged in as: {session['saml_nameid']}<br><br>Attributes:<br>{session['saml_user_data']}"
        # return redirect(url_for('welcome'))
    else:
        return f"❌ SAML Error: {errors}"
    

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
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)




