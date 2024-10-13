from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import pandas as pd
from pymongo import MongoClient
import os
import matplotlib
matplotlib.use('Agg')  # Use a non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
import logging
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score
import uuid
from bson.objectid import ObjectId
from datetime import datetime, timezone
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb  # XGBoost for the XGBClassifier
from sklearn.linear_model import LogisticRegression  # Meta-model for stacking
from sklearn.model_selection import train_test_split


# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')  # Use environment variable for production

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# MongoDB client setup
try:
    client = MongoClient('mongodb+srv://ravi:Qwert123@maincluster.ff8x9.mongodb.net/?retryWrites=true&w=majority')
    db = client['malware_detection_db']
    users_collection = db['users']
    dataset_collection = db['datasets']
    questions_collection = db['questions']

    logging.info("MongoDB connection established for user authentication and dataset storage.")
except Exception as e:
    logging.error("MongoDB connection failed: %s", e)
    exit(1)  # Exit the app if the database connection fails

# Directory for saving uploaded datasets locally
uploads_dir = 'uploads'
if not os.path.exists(uploads_dir):
    os.makedirs(uploads_dir)
    logging.info(f"Created directory for uploads: {uploads_dir}")

# Check allowed file extensions
ALLOWED_EXTENSIONS = {'csv'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

MALWARE_KEYWORDS = {
    'worm': ['worm'],
    'trojan': ['trojan', 'trojan horse'],
    'spyware': ['spyware'],
    'ransomware': ['ransomware'],
    'adware': ['adware'],
    'rootkit': ['rootkit'],
    'keylogger': ['keylogger'],
    'botnet': ['botnet'],
    'phishing': ['phishing'],
    'malware': ['malware'],
    'virus': ['virus'],
    'backdoor': ['backdoor'],
    'exploit': ['exploit', 'exploit kit'],
    'downloader': ['downloader'],
    'scareware': ['scareware'],
    'crypto': ['crypto', 'cryptojacker'],
    'flooder': ['flooder'],
    'DDoS': ['ddos', 'distributed denial of service'],
    'zero-day': ['zero-day'],
    'remote access trojan': ['remote access trojan', 'rat'],
    'infostealer': ['infostealer']
}


@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch the user from the database
        user = users_collection.find_one({'username': username, 'password': password})
        
        if user:
            # Store session data
            session['username'] = username
            session['role'] = user['role']
            
            # Check the user's role and redirect accordingly
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'user':
                return redirect(url_for('user_dashboard'))
        else:
            # If credentials are invalid, show an error message
            flash('Invalid credentials')
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    # Validate input
    if not username or not password or not role:
        flash('All fields are required.')
        return redirect(url_for('admin_dashboard'))

    # Check if user already exists
    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        flash('User already exists.')
        return redirect(url_for('admin_dashboard'))

    # Add new user to the database
    users_collection.insert_one({
        'username': username,
        'password': password,  # Note: In production, make sure to hash passwords
        'role': role
    })

    flash('User added successfully.')
    return redirect(url_for('admin_dashboard'))


@app.route('/manage_users_data', methods=['GET'])
def manage_users_data():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    users = list(users_collection.find())
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string for JSON serialization

    return jsonify({'users': users})

# Add a route to view all users (only accessible to admins)
@app.route('/manage_users')
def manage_users():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    # Fetch the list of users from the database
    users = list(users_collection.find())

    # Ensure ObjectIds are converted to strings so they can be passed into the template
    for user in users:
        user['_id'] = str(user['_id'])

    # Pass the 'users' variable to the template
    return render_template('admin_dashboard.html', users=users)


@app.route('/update_user/<user_id>', methods=['POST'])
def update_user(user_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    # Get the data from the request
    data = request.get_json()
    new_role = data.get('role')
    new_password = data.get('new_password')

    if not new_role:
        return jsonify({'error': 'Role cannot be empty!'}), 400

    # Update the user's role
    update_data = {'role': new_role}

    # If a new password is provided, add it to the update
    if new_password:
        update_data['password'] = new_password

    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})

    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    users_collection.delete_one({'_id': ObjectId(user_id)})

    return jsonify({'message': 'User deleted successfully'}), 200




@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')


@app.route('/upload_dataset', methods=['POST'])
def upload_dataset():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{uuid.uuid4()}.csv"
        file_path = os.path.join(uploads_dir, filename)
        file.save(file_path)
        session['latest_dataset'] = file_path
        return jsonify({'message': f'Dataset uploaded successfully as {filename}!'}), 200
    return jsonify({'error': 'Invalid file or no file uploaded.'}), 400

def get_latest_dataset():
    """Helper function to get the path of the latest uploaded dataset."""
    try:
        datasets = [os.path.join(uploads_dir, f) for f in os.listdir(uploads_dir) if f.endswith('.csv')]
        latest_file = max(datasets, key=os.path.getmtime, default=None)
        return latest_file
    except Exception as e:
        logging.error(f"Error finding latest dataset: {e}")
        return None
    
def get_user_latest_dataset():
    """Helper function to get the path of the latest uploaded dataset for user."""
    try:
        datasets = [os.path.join(uploads_dir, f) for f in os.listdir(uploads_dir) if f.startswith('user_') and f.endswith('.csv')]
        latest_file = max(datasets, key=os.path.getmtime, default=None)
        return latest_file
    except Exception as e:
        logging.error(f"Error finding latest dataset: {e}")
        return None
    
def get_last_3_datasets():
    datasets = [os.path.join(uploads_dir, f) for f in os.listdir(uploads_dir) if f.endswith('.csv')]
    datasets.sort(key=os.path.getmtime, reverse=True)  # Sort by timestamp
    logging.info(f"Datasets found: {datasets[:3]}")  # Log the datasets being loaded
    last_3_datasets = datasets[:3]  # Get the last 3 datasets
    return last_3_datasets


@app.route('/data_visualization', methods=['GET'])
def data_visualization():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    try:
        # Get the latest uploaded dataset
        latest_dataset_path = get_latest_dataset()
        if not latest_dataset_path:
            return jsonify({'error': 'No dataset available for visualization.'}), 400

        # Read the dataset
        dataset = pd.read_csv(latest_dataset_path)

        # List of possible column names for category (case-insensitive)
        possible_category_columns = ['category', 'malware_category', 'mal_cat', 'mal_category']

        # List of possible column names for family (case-insensitive)
        possible_family_columns = ['family', 'malware_family', 'mal_fam', 'mal_family']

        # Find the column that matches one of the possible category column names (case-insensitive)
        category_column = None
        for col in dataset.columns:
            if col.lower() in [name.lower() for name in possible_category_columns]:
                category_column = col
                break

        # Find the column that matches one of the possible family column names (case-insensitive)
        family_column = None
        for col in dataset.columns:
            if col.lower() in [name.lower() for name in possible_family_columns]:
                family_column = col
                break

        # If neither category nor family columns are found, return an error
        if not category_column and not family_column:
            return jsonify({'error': 'No suitable columns found for either malware categories or families.'}), 400

        # Initialize an empty list to hold the two visualizations
        visualizations = {}

        # Generate the bar chart for malware categories (if the category column is found)
        if category_column:
            malware_category_counts = dataset[category_column].value_counts()
            if malware_category_counts.empty:
                return jsonify({'error': 'No data to display in the category column.'}), 400

            # Plotting the distribution of categories
            plt.figure(figsize=(10, 6))
            malware_category_counts.plot(kind='bar', color='skyblue')
            plt.xlabel('Malware Category')
            plt.ylabel('Count')
            plt.title(f'Distribution of Malware Categories (Column: {category_column})')

            # Save category plot to buffer
            buf_cat = io.BytesIO()
            plt.savefig(buf_cat, format='png')
            buf_cat.seek(0)
            encoded_category_image = base64.b64encode(buf_cat.getvalue()).decode('utf-8')
            buf_cat.close()

            # Add the category graph to the visualizations list
            visualizations['category_visualization'] = encoded_category_image

        # Generate the bar chart for malware families (if the family column is found)
        if family_column:
            malware_family_counts = dataset[family_column].value_counts()
            if malware_family_counts.empty:
                return jsonify({'error': 'No data to display in the family column.'}), 400

            # Plotting the distribution of families
            plt.figure(figsize=(10, 6))
            malware_family_counts.plot(kind='bar', color='lightcoral')
            plt.xlabel('Malware Family')
            plt.ylabel('Count')
            plt.title(f'Distribution of Malware Families (Column: {family_column})')

            # Save family plot to buffer
            buf_fam = io.BytesIO()
            plt.savefig(buf_fam, format='png')
            buf_fam.seek(0)
            encoded_family_image = base64.b64encode(buf_fam.getvalue()).decode('utf-8')
            buf_fam.close()

            # Add the family graph to the visualizations list
            visualizations['family_visualization'] = encoded_family_image

        # If no visualizations were created, return an error
        if not visualizations:
            return jsonify({'error': 'No suitable data found to generate visualizations.'}), 400

        # Return both visualizations in JSON format
        return jsonify(visualizations), 200

    except Exception as e:
        logging.error(f"Error generating visualization: {e}")
        return jsonify({'error': f'An error occurred while generating visualization: {str(e)}'}), 500

from sklearn.preprocessing import LabelEncoder

from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

@app.route('/admin_prediction', methods=['POST'])
def admin_prediction():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    try:
        # Load the last 3 datasets for admin
        dataset_paths = get_last_3_datasets()
        if not dataset_paths:
            return jsonify({'error': 'No datasets available for prediction.'}), 400

        # Log the dataset paths being used for prediction
        logging.info(f"Datasets used for prediction: {dataset_paths}")

        # Combine all datasets into a single dataframe
        dataframes = [pd.read_csv(path) for path in dataset_paths]
        combined_dataset = pd.concat(dataframes, ignore_index=True)  # Ensuring correct concatenation

        # Define possible column names for categories and families
        possible_category_columns = ['category', 'malware_category', 'mal_cat', 'mal_category']
        possible_family_columns = ['family', 'malware_family', 'mal_fam', 'mal_family']

        # Find relevant columns
        category_column = next((col for col in combined_dataset.columns if col.lower() in possible_category_columns), None)
        family_column = next((col for col in combined_dataset.columns if col.lower() in possible_family_columns), None)

        if not category_column or not family_column:
            return jsonify({'error': 'No suitable columns found for either malware categories or families.'}), 400

        # Log the found columns for category and family
        logging.info(f"Category column found: {category_column}")
        logging.info(f"Family column found: {family_column}")

        # Log the counts of each malware family and category across all datasets
        family_counts = combined_dataset[family_column].value_counts()
        category_counts = combined_dataset[category_column].value_counts()

        logging.info(f"Family counts across all datasets:\n{family_counts}")
        logging.info(f"Category counts across all datasets:\n{category_counts}")

        # Feature selection (drop target columns)
        X = combined_dataset.drop(columns=[family_column, category_column], errors='ignore')
        y_family = combined_dataset[family_column]
        y_category = combined_dataset[category_column]

        # One-hot encode non-numeric columns
        non_numeric_columns = X.select_dtypes(include=['object']).columns.tolist()
        X_encoded = pd.get_dummies(X, columns=non_numeric_columns, drop_first=True)

        # Encode the family and category labels to numerical values
        family_encoder = LabelEncoder()
        category_encoder = LabelEncoder()

        y_family_encoded = family_encoder.fit_transform(y_family)
        y_category_encoded = category_encoder.fit_transform(y_category)

        # Train-test split
        X_train, X_test, y_train_family, y_test_family = train_test_split(X_encoded, y_family_encoded, test_size=0.2, random_state=42)
        _, _, y_train_category, y_test_category = train_test_split(X_encoded, y_category_encoded, test_size=0.2, random_state=42)

        # Train Random Forest and XGBoost for family prediction
        rf_family = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_family.fit(X_train, y_train_family)

        xgb_family = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
        xgb_family.fit(X_train, y_train_family)

        # Get predictions for family
        rf_family_pred = rf_family.predict(X_test)
        xgb_family_pred = xgb_family.predict(X_test)

        # Train Random Forest and XGBoost for category prediction
        rf_category = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_category.fit(X_train, y_train_category)

        xgb_category = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
        xgb_category.fit(X_train, y_train_category)

        # Get predictions for category
        rf_category_pred = rf_category.predict(X_test)
        xgb_category_pred = xgb_category.predict(X_test)

        # Stacking: Use predictions as inputs to a meta-model (Logistic Regression)
        stacked_family_predictions = np.column_stack((rf_family_pred, xgb_family_pred))
        stacked_category_predictions = np.column_stack((rf_category_pred, xgb_category_pred))

        # Meta-model for family prediction
        meta_model_family = LogisticRegression()
        meta_model_family.fit(stacked_family_predictions, y_test_family)
        final_family_pred = meta_model_family.predict(stacked_family_predictions)

        # Meta-model for category prediction
        meta_model_category = LogisticRegression()
        meta_model_category.fit(stacked_category_predictions, y_test_category)
        final_category_pred = meta_model_category.predict(stacked_category_predictions)

        # Decode predictions back to original string labels
        final_family_pred_decoded = family_encoder.inverse_transform(final_family_pred)
        final_category_pred_decoded = category_encoder.inverse_transform(final_category_pred)

        # Log the decoded family and category predictions
        logging.info(f"Final family predictions (decoded): {final_family_pred_decoded}")
        logging.info(f"Final category predictions (decoded): {final_category_pred_decoded}")

        # Summarize predictions
        most_common_family = pd.Series(final_family_pred_decoded).mode()[0]
        least_common_family = pd.Series(final_family_pred_decoded).value_counts().idxmin()
        most_common_category = pd.Series(final_category_pred_decoded).mode()[0]
        least_common_category = pd.Series(final_category_pred_decoded).value_counts().idxmin()

        # Log the final summary of predictions
        logging.info(f"Most common family: {most_common_family}, Least common family: {least_common_family}")
        logging.info(f"Most common category: {most_common_category}, Least common category: {least_common_category}")

        prediction_summary = {
            'most_common_family': most_common_family,
            'least_common_family': least_common_family,
            'most_common_category': most_common_category,
            'least_common_category': least_common_category
        }

        return jsonify({'summary': prediction_summary}), 200

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500


@app.route('/user_dashboard', methods=['GET'])
def user_dashboard():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    return render_template('user_dashboard.html')

@app.route('/user_upload_dataset', methods=['POST'])
def user_upload_dataset():
    if 'username' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized access.'}), 403

    file = request.files.get('file')
    if file and allowed_file(file.filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{uuid.uuid4()}.csv"
        file_path = os.path.join(uploads_dir, filename)
        file.save(file_path)
        session['user_latest_dataset'] = file_path
        
        # Return success message
        return jsonify({'message': f'Dataset uploaded successfully as {filename}!'}), 200
    return jsonify({'error': 'Invalid file or no file uploaded.'}), 400

@app.route('/view_answered_questions', methods=['GET'])
def view_answered_questions():
    try:
        # Fetch questions with status 'answered' from questions_collection
        answered_questions = list(questions_collection.find({'status': 'answered'}))

        # Convert ObjectId to string for each question
        for question in answered_questions:
            question['_id'] = str(question['_id'])  # Convert ObjectId to string

        # Return the answered questions in the JSON response
        return jsonify({
            'answered_questions': answered_questions
        }), 200
    except Exception as e:
        logging.error(f"Error fetching answered questions: {e}")
        return jsonify({'error': 'An error occurred while fetching answered questions.'}), 500

@app.route('/submit_question', methods=['POST'])
def submit_question():
    if 'username' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized access.'}), 403

    question_text = request.form['question']
    
    if not question_text:
        return jsonify({'error': 'Question cannot be empty!'}), 400

    question = {
        'question': question_text,
        'user': session['username'],
        'answer': None,  # Answer is empty initially
        'admin': None,
        'status': 'unanswered',
        'timestamp': datetime.utcnow()
    }
    
    questions_collection.insert_one(question)
    
    return jsonify({'message': 'Question submitted successfully!'}), 200

@app.route('/submit_answer/<question_id>', methods=['POST'])
def submit_answer(question_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    answer_text = request.json.get('answer')

    if not answer_text:
        return jsonify({'error': 'Answer cannot be empty!'}), 400

    question = questions_collection.find_one({'_id': ObjectId(question_id)})
    
    if not question:
        return jsonify({'error': 'Question not found!'}), 404

    # Update the question with the answer
    questions_collection.update_one(
        {'_id': ObjectId(question_id)},
        {
            '$set': {
                'answer': answer_text,
                'admin': session['username'],
                'status': 'answered',
                'answered_timestamp': datetime.now(timezone.utc)  # Add answered timestamp
            }
        }
    )
    
    return jsonify({'message': 'Answer submitted successfully!'}), 200

@app.route('/view_all_questions', methods=['GET'])
def view_all_questions():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access.'}), 403

    all_questions = list(questions_collection.find({}))

    # Log all questions for debugging
    logging.info(f"All questions fetched: {all_questions}")

    # Format ObjectId to string for JSON serialization
    for question in all_questions:
        question['_id'] = str(question['_id'])

    return jsonify({'all_questions': all_questions}), 200


@app.route('/user_data_visualization', methods=['GET'])
def user_data_visualization():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    try:
        # Get the latest uploaded dataset from the session
        latest_dataset_path = session.get('user_latest_dataset', None)
        if not latest_dataset_path:
            return jsonify({'error': 'No dataset available for visualization.'}), 400

        # Ensure the dataset exists and can be read
        if not os.path.exists(latest_dataset_path):
            return jsonify({'error': 'Dataset file not found.'}), 400

        # Read the dataset
        dataset = pd.read_csv(latest_dataset_path)

        # Define possible column names
        possible_category_columns = ['category', 'malware_category', 'mal_cat', 'mal_category']
        possible_family_columns = ['family', 'malware_family', 'mal_fam', 'mal_family']

        # Find the relevant columns
        category_column = next((col for col in dataset.columns if col.lower() in possible_category_columns), None)
        family_column = next((col for col in dataset.columns if col.lower() in possible_family_columns), None)

        # Initialize an empty dictionary to hold visualizations
        visualizations = {}

        # Generate the bar chart for malware categories if the column is found
        if category_column:
            malware_category_counts = dataset[category_column].value_counts()
            if malware_category_counts.empty:
                return jsonify({'error': 'No data to display in the category column.'}), 400

            # Create the plot
            plt.figure(figsize=(10, 6))
            malware_category_counts.plot(kind='bar', color='skyblue')
            plt.xlabel('Malware Category')
            plt.ylabel('Count')
            plt.title(f'Distribution of Malware Categories (Column: {category_column})')
            
            # Apply tight layout and rotate x-axis labels
            plt.tight_layout()
            plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels for better readability

            # Save the plot to a buffer and encode it
            buf_cat = io.BytesIO()
            plt.savefig(buf_cat, format='png')
            buf_cat.seek(0)
            encoded_category_image = base64.b64encode(buf_cat.getvalue()).decode('utf-8')
            buf_cat.close()

            # Add the plot to the visualizations dictionary
            visualizations['category_visualization'] = encoded_category_image

        # Generate the bar chart for malware families if the column is found
        if family_column:
            malware_family_counts = dataset[family_column].value_counts()
            if malware_family_counts.empty:
                return jsonify({'error': 'No data to display in the family column.'}), 400

            # Create the plot
            plt.figure(figsize=(10, 6))
            malware_family_counts.plot(kind='bar', color='lightcoral')
            plt.xlabel('Malware Family')
            plt.ylabel('Count')
            plt.title(f'Distribution of Malware Families (Column: {family_column})')

            # Apply tight layout and rotate x-axis labels
            plt.tight_layout()
            plt.xticks(rotation=45, ha='right')  # Rotate x-axis labels for better readability

            # Save the plot to a buffer and encode it
            buf_fam = io.BytesIO()
            plt.savefig(buf_fam, format='png')
            buf_fam.seek(0)
            encoded_family_image = base64.b64encode(buf_fam.getvalue()).decode('utf-8')
            buf_fam.close()

            # Add the plot to the visualizations dictionary
            visualizations['family_visualization'] = encoded_family_image

        # If neither category nor family visualizations were created, return an error
        if not visualizations:
            return jsonify({'error': 'No suitable data found to generate visualizations.'}), 400

        # Return the visualizations as JSON
        return jsonify(visualizations), 200

    except Exception as e:
        logging.error(f"Error generating visualization: {e}")
        return jsonify({'error': f'An error occurred while generating visualization: {str(e)}'}), 500

@app.route('/user_prediction', methods=['POST'])
def user_prediction():
    if 'username' not in session or session['role'] != 'user':
        return jsonify({'error': 'Unauthorized access.'}), 403

    try:
        # Load the last 3 datasets
        dataset_paths = get_last_3_datasets()  # This function retrieves the paths to the last 3 datasets
        if not dataset_paths:
            return jsonify({'error': 'No datasets available for prediction.'}), 400

        # Combine all datasets into a single dataframe
        dataframes = [pd.read_csv(path) for path in dataset_paths]
        combined_dataset = pd.concat(dataframes)

        # List of possible column names for category and family (case-insensitive)
        possible_category_columns = ['category', 'malware_category', 'mal_cat', 'mal_category']
        possible_family_columns = ['family', 'malware_family', 'mal_fam', 'mal_family']

        # Find the column that matches one of the possible category column names (case-insensitive)
        category_column = None
        for col in combined_dataset.columns:
            if col.lower() in [name.lower() for name in possible_category_columns]:
                category_column = col
                break

        # Find the column that matches one of the possible family column names (case-insensitive)
        family_column = None
        for col in combined_dataset.columns:
            if col.lower() in [name.lower() for name in possible_family_columns]:
                family_column = col
                break

        # If neither category nor family columns are found, return an error
        if not category_column or not family_column:
            return jsonify({'error': 'No suitable columns found for either malware categories or families.'}), 400

        # Perform the counting for family and category
        family_counts = combined_dataset[family_column].value_counts()
        category_counts = combined_dataset[category_column].value_counts()

        # Logging for debugging purposes
        logging.info(f"Family counts: {family_counts}")
        logging.info(f"Category counts: {category_counts}")

        # Find most and least common for family
        most_common_family = family_counts.idxmax() if not family_counts.empty else None
        least_common_family = family_counts.idxmin() if not family_counts.empty else None

        # Find most and least common for category
        most_common_category = category_counts.idxmax() if not category_counts.empty else None
        least_common_category = category_counts.idxmin() if not category_counts.empty else None

        # Prepare the prediction summary
        prediction_summary = {
            'most_common_family': most_common_family,
            'least_common_family': least_common_family,
            'most_common_category': most_common_category,
            'least_common_category': least_common_category
        }

        # Return the result as JSON
        return jsonify({'summary': prediction_summary}), 200

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the session to log the user out
    session.clear()
    
    # Redirect to the login page (or any other page)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
