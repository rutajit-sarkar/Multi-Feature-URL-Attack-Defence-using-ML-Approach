import streamlit as st
import pandas as pd
import pickle
from preprocess import preprocess_url
import datetime
import sqlite3
import matplotlib.pyplot as plt

# Load the model
model = pickle.load(open('model.pkl', 'rb'))


# Database functions
def create_db():
    conn = sqlite3.connect('url_predictions.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            prediction INTEGER,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_data_to_db(url, prediction):
    conn = sqlite3.connect('url_predictions.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO url_predictions (url, prediction, timestamp)
        VALUES (?, ?, ?)
    ''', (url, prediction, str(datetime.datetime.now())))
    conn.commit()
    conn.close()

def display_all_data():
    conn = sqlite3.connect('url_predictions.db')
    c = conn.cursor()
    c.execute('SELECT * FROM url_predictions')
    data = c.fetchall()
    conn.close()
    return data

# Load CSV data (if needed)
def load_data(file_path, encoding='utf-8', errors='ignore'):
    data = pd.read_csv(file_path, encoding=encoding, errors=errors)
    return data

# Main function for the Streamlit app
def main():
    st.title("Malicious URL Detection :shield: :desktop_computer:")
    st.write("Enter a URL to predict if it's malicious or not:")
    
    # Input URL from the user
    url = st.text_input("URL:")
    
    if st.button("Predict"):
        if url:
            # Preprocess the URL
            processed_url = preprocess_url(url)
            # Make predictions
            prediction = model.predict(processed_url)
            if prediction == 1:
                st.error("This URL is malicious!")
            else:
                st.success("This URL is safe.")
            
            # Store the input URL and prediction in the database
            add_data_to_db(url, int(prediction))
        else:
            st.warning("Please enter a URL.")
    
    # Display all data from the database
    st.write("## All Predictions")
    data = display_all_data()
    df = pd.DataFrame(data, columns=['ID', 'URL', 'Prediction', 'Timestamp'])
    
    # Handle any potential encoding issues when displaying the DataFrame
    df = df.applymap(lambda x: str(x) if isinstance(x, bytes) else x)
    st.dataframe(df)

# Create the database and table if they don't exist
create_db()

if __name__ == "__main__":
    main()
