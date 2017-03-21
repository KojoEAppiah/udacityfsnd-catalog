from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Item, Catagory, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CatalogApp"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
# Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

itemcount = 0


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None:
        if gplus_id == stored_gplus_id:
            response = make_response(json.dumps(
                'Current user is already connected.'),
                                 200)
            response.headers['Content-Type'] = 'application/json'
            return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
    url = url % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/clearSession')
def clearSession():
    login_session.clear()
    return "Session cleared"


# JSON APIs to view Restaurant Information
@app.route('/catalog/<string:catagory_name>/JSON')
def catagoryJSON(catagory_name):
    catagory = session.query(Catagory).filter_by(name=catagory_name).one()
    items = session.query(Item).filter_by(
        catagory_name=catagory_name).all()
    return jsonify(CatagoryItems=[i.serialize for i in items])


@app.route('/catalog/<int:item_id>/JSON')
def itemJSON(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(loneItem=item.serialize)


@app.route('/catalog/JSON')
def catalogJSON():
    catagories = session.query(Catagory).all()
    return jsonify(catagories=[c.serialize for c in catagories])


# Show all restaurants
@app.route('/')
@app.route('/catalog/')
def frontPage():
    catagories = session.query(Catagory).order_by(Catagory.name)
    items = session.query(Item).order_by(Item.id.desc())

    return render_template("mainpage.html", catagories=catagories, items=items)

# Create a new restaurant


@app.route('/catalog/newcatagory/', methods=['GET', 'POST'])
def newCatagory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':

        name = request.form['name']
        if not session.query(Catagory).filter_by(name=name).all():
            newCatagory = Catagory(name=name)
            session.add(newCatagory)
            flash('New Catagory %s Successfully Created' % newCatagory.name)
            session.commit()
            print name
            return redirect(url_for('frontPage'))

        else:
            error = "A catagory with that name already exists."
            render_template('newCatagory.html', name=name, error=error)

    else:
        return render_template('newCatagory.html')


# Edit a restaurant
@app.route('/catalog/editcatagory/<string:catagory>', methods=['GET', 'POST'])
def editCatagory(catagory):

    if 'username' not in login_session:
        return redirect('/login')

    editedCatagory = session.query(
        Catagory).filter_by(name=catagory).first()

    if request.method == 'POST':
        if request.form['name']:
            editedCatagory.name = request.form['name']
            flash('Catagory Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('frontPage'))
    else:
        return render_template('editCatagory.html', catagory=catagory)


# Delete a restaurant
@app.route('/catalog/deletecatagory/<string:catagory>',
           methods=['GET', 'POST'])
def deleteCatagory(catagory):

    if 'username' not in login_session:
        return redirect('/login')

    catagoryToDelete = session.query(
        Catagory).filter_by(name=catagory).first()
    print catagory

    if request.method == 'POST' and catagoryToDelete:
        items = session.query(Item).filter_by(catagory_name=catagory).all()
        for item in items:
            session.delete(item)
        session.delete(catagoryToDelete)
        flash('%s Successfully Deleted' % catagoryToDelete.name)
        session.commit()
        return redirect(url_for('frontPage'))
    else:
        return render_template('deleteCatagory.html', catagory=catagory)

# Show a restaurant menu


@app.route('/catalog/<string:catagory>/items')
def showCatagory(catagory):

    items = session.query(Item).filter_by(
        catagory_name=catagory).order_by(Item.id.desc()).all()

    catagories = session.query(Catagory).order_by(Catagory.name).all()

    return render_template('showCatagory.html', catagories=catagories,
                           currCatagory=catagory,
                           numItems=len(items), items=items)


# Create a new item
@app.route('/catalog/newitem', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':

        name = request.form['name']
        description = request.form['description']
        catagory_name = request.form['catagory'].replace('\n', '')

        if not session.query(Catagory).filter_by(name=catagory_name).all():
            catagory = Catagory(name=catagory_name)
            session.add(catagory)

        newItem = Item(name=name, description=description,
                       catagory_name=catagory_name,
                       user_id=session.query(User).filter_by(
                        email=login_session['email']).first().id)
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('frontPage'))
    else:
        return render_template('newItem.html')

# Edit a menu item


@app.route('/catalog/edititem/<int:item_id>', methods=['GET', 'POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    print login_session['username']
    editedItem = session.query(Item).filter_by(id=item_id).one()

    catagories = session.query(Catagory).order_by(Catagory.name).all()
    print "Catagories: %d" % len(catagories)
    if editedItem.user_id != login_session['user_id']:
        return redirect(url_for("unauthorized"))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        catagory = request.form['catagory'].replace('\n', '')

        editedItem.name = name
        editedItem.description = description
        editedItem.catagory_name = catagory

        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('frontPage'))

    else:
        return render_template('editItem.html', item=editedItem,
                               catagories=catagories)


# Delete a menu item
@app.route('/catalog/deleteitem/<int:item_id>', methods=['GET', 'POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    itemToDelete = session.query(Item).filter_by(id=item_id).one()

    if itemToDelete.user_id != login_session['user_id']:
        return redirect(url_for("unauthorized"))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('frontPage'))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


@app.route('/catalog/showitem/<int:item_id>', methods=['GET', 'POST'])
def showItem(item_id):
    item = session.query(Item).filter_by(id=item_id).first()

    if item:
        return render_template('showItem.html', item=item)


@app.route('/unauthorized', methods=['GET'])
def unauthorized():
    return render_template("unauthorized.html")

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
