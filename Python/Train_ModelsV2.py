import os
import pandas as pd
import joblib
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical

# Define column names based on the provided feature list
column_names = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
    "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
    "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "Label"
]

# List of all dataset files
dataset_files = [
    'C:\\Users\\griff\\OneDrive\\Desktop\\HEDA Modules\\UNSW_NB15\\UNSW-NB15_1.csv',
    'C:\\Users\\griff\\OneDrive\\Desktop\\HEDA Modules\\UNSW_NB15\\UNSW-NB15_2.csv',
    'C:\\Users\\griff\\OneDrive\\Desktop\\HEDA Modules\\UNSW_NB15\\UNSW-NB15_3.csv',
    'C:\\Users\\griff\\OneDrive\\Desktop\\HEDA Modules\\UNSW_NB15\\UNSW-NB15_4.csv'
]

# Load and concatenate all datasets
data_frames = [pd.read_csv(file, header=None, names=column_names, low_memory=False) for file in dataset_files]
data_df = pd.concat(data_frames, ignore_index=True)

# Convert non-numeric columns that should be numeric to numeric, replacing non-convertible values with NaN
data_df['sport'] = pd.to_numeric(data_df['sport'], errors='coerce')
data_df['dsport'] = pd.to_numeric(data_df['dsport'], errors='coerce')

# Replace NaN values with a chosen number, for example 0
data_df.fillna(0, inplace=True)

# 'attack_cat' is the target variable, separate the features and target
X = data_df.drop('attack_cat', axis=1)
y = data_df['attack_cat'].astype(str)  # Ensure attack categories are strings

# Convert IP addresses to strings to ensure proper one-hot encoding
data_df['srcip'] = data_df['srcip'].astype(str)
data_df['dstip'] = data_df['dstip'].astype(str)

# Encode the labels (attack categories)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
y_onehot = to_categorical(y_encoded)

# Create the directory if it does not exist
os.makedirs('Python/Models', exist_ok=True)

# Save the label encoder for later use
joblib.dump(label_encoder, 'Python/Models/label_encoder.joblib')

# Updated preprocessor with handle_unknown='ignore' and initial features
selected_features = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'service'
]

preprocessor = ColumnTransformer(
    transformers=[
        ('onehot', OneHotEncoder(handle_unknown='ignore'), ['srcip', 'dstip', 'proto', 'state', 'service']),
        ('scaler', StandardScaler(), ['sport', 'dsport', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl'])
    ],
    remainder='passthrough'
)

# Apply the preprocessor to the selected features
X_processed = preprocessor.fit_transform(X[selected_features])

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_processed, y_onehot, test_size=0.3, random_state=42)

# Initialize the Isolation Forest model
iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
iso_forest.fit(X_train)

# Save the Isolation Forest model
joblib.dump(iso_forest, 'Python/Models/isolation_forest_model.joblib')

# Define the neural network model architecture
model = Sequential([
    Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    Dropout(0.5),
    Dense(64, activation='relu'),
    Dense(y_onehot.shape[1], activation='softmax')  # Multi-class classification
])

# Compile the model with optimizer, loss function, and metrics
model.compile(optimizer='adam',
              loss='categorical_crossentropy',
              metrics=['accuracy'])

# Train the model on the processed training data
model.fit(X_train, y_train, epochs=5, batch_size=32, validation_split=0.1)

# Evaluate the model on the test set
test_loss, test_acc = model.evaluate(X_test, y_test, verbose=2)
print(f'Test accuracy: {test_acc}')

# Save the neural network model
model.save('Python/Models/deep_learning_model.h5')

# Make predictions on the test set
predictions = model.predict(X_test)
predictions_classes = predictions.argmax(axis=-1)
y_test_classes = y_test.argmax(axis=-1)

# Generate a classification report
report = classification_report(y_test_classes, predictions_classes, target_names=label_encoder.classes_)
print(report)

report_dict = classification_report(y_test_classes, predictions_classes, target_names=label_encoder.classes_, output_dict=True)
report_df = pd.DataFrame(report_dict).transpose()

# Save the classification report to a JSON file
with open('Python/Models/classification_report.json', 'w') as f:
    json.dump(report_dict, f, indent=4)

# Save the preprocessor for later use during prediction on new data
joblib.dump(preprocessor, 'Python/Models/preprocessor.joblib')
