from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Ecommerce Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///ecommerce.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Check the login status of a user
def login_required(f):
    '''Checks to see whether a user is logged in'''
    @wraps(f)
    def check(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return check

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Connect
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

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('''Current user is
                                            already connected.'''), 200)
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

    # see if user exists, if it doesn't, make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px;border-radius: 1
              50px;-webkit-border-radius:
              150px;-moz-border-radius: 150px;"> '''
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
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('You are now successfully logged out.')
        return redirect(url_for('showCategories'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category&Item Information
@app.route('/category/<int:category_id>/items/JSON')
def categoryItemsJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def categoryItemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# Three levels of showcasing: categories, items within one category, one item
# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    # return render_template('showCategory.html', categories=categories)
    return render_template('showCategories.html', categories=categories)


# Show all items in a category
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showItems(category_id):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return render_template('showItems.html', items=items,
                           category=category, categories=categories)


# Show a single item
@app.route('/category/<int:category_id>/items/<int:item_id>/')
def showItem(category_id, item_id):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('showItem.html', item=item,
                           category=category, categories=categories)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        name = request.form['name']
        image = request.form['image']
        if not name:
            error_message = "Name cannot be empty."
            return render_template('newCategory.html',
                                   error_message=error_message)
        elif not image:
            error_message = "Image URL cannot be empty."
            return render_template('newCategory.html',
                                   error_message=error_message)
        newCategory = Category(name=name, image=image,
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('New Category %s is Successfully Created' % newCategory.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        flash('''Sorry, but you cannot edit this category.
              Please create your own category in order to edit.''')
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        name = request.form['name']
        image = request.form['image']
        if not name:
            error_message = "Name cannot be empty."
            return render_template('editCategory.html',
                                   error_message=error_message,
                                   category=editedCategory)
        elif not image:
            error_message = "Image URL cannot be empty."
            return render_template('editCategory.html',
                                   error_message=error_message,
                                   category=editedCategory)
        editedCategory.name = name
        editedCategory.image = image
        session.add(editedCategory)
        session.commit()
        flash('Successfully Edited Category %s' % editedCategory.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    deletedCategory = session.query(Category).filter_by(id=category_id).one()
    if deletedCategory.user_id != login_session['user_id']:
        flash('''Sorry, but you cannot delete this category.
              Please create your own category in order to delete.''')
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        session.delete(deletedCategory)
        session.commit()
        flash('Successfully Deleted %s' % deletedCategory.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html', category=deletedCategory)


# Create a new category item
@app.route('/category/<int:category_id>/items/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        name = request.form['name']
        image = request.form['image']
        description = request.form['description']
        price = request.form['price']
        if not name:
            error_message = "Name cannot be empty."
            return render_template('newItem.html', category_id=category_id,
                                   error_message=error_message)
        elif not image:
            error_message = "Image URL cannot be empty."
            return render_template('newItem.html', category_id=category_id,
                                   error_message=error_message)
        elif not description:
            error_message = "Description cannot be empty."
            return render_template('newItem.html', category_id=category_id,
                                   error_message=error_message)
        elif not price:
            error_message = "Price cannot be empty."
            return render_template('newItem.html', category_id=category_id,
                                   error_message=error_message)
        newItem = Item(name=name, image=image,
                       description=description, price=price,
                       category_id=category_id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        category.quantity = category.quantity + 1
        session.add(category)
        session.commit()

        flash('New Item %s is Successfully Created' % (newItem.name))
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('newItem.html', category_id=category_id)


# Edit a category item
@app.route('/category/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editItem(category_id, item_id):
    editedItem = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        flash('''Sorry, but you cannot edit this category item.
              Please create your own category in order to edit.''')
        return redirect(url_for('showItem', category_id=category_id,
                                item_id=item_id))
    if request.method == 'POST':
        name = request.form['name']
        image = request.form['image']
        description = request.form['description']
        price = request.form['price']
        if not name:
            error_message = "Name cannot be empty."
            return render_template('editItem.html', category_id=category_id,
                                   error_message=error_message,
                                   item_id=item_id, item=editedItem)
        elif not image:
            error_message = "Image URL cannot be empty."
            return render_template('editItem.html', category_id=category_id,
                                   error_message=error_message,
                                   item_id=item_id, item=editedItem)
        elif not description:
            error_message = "Description cannot be empty."
            return render_template('editItem.html', category_id=category_id,
                                   error_message=error_message,
                                   item_id=item_id, item=editedItem)
        elif not price:
            error_message = "Price cannot be empty."
            return render_template('editItem.html', category_id=category_id,
                                   error_message=error_message,
                                   item_id=item_id, item=editedItem)
        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
        editedItem.price = request.form['price']
        editedItem.image = request.form['image']
        session.add(editedItem)
        session.commit()
        flash('Successfully Edited Item %s ' % (editedItem.name))
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('editItem.html', category_id=category_id,
                               item_id=item_id, item=editedItem)


# Delete a category item
@app.route('/category/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != category.user_id:
        flash('''Sorry, but you cannot delete this category item.
                Please create your own category in order to delete.''')
        return redirect(url_for('showItem',
                        category_id=category_id, item_id=item_id))
    name = itemToDelete.name
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        category.quantity = category.quantity - 1
        session.add(category)
        session.commit()
        flash('Successfully Deleted Item %s ' % name)
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteItem.html', item=itemToDelete,
                               category_id=category_id,  item_id=item_id)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
