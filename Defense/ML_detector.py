import numpy as np
import csv
import os
import random
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import roc_auc_score, roc_curve, f1_score
from tensorflow.python.keras.layers import Dense, Input
from tensorflow.python.keras.models import Model
import matplotlib.pyplot as plt
from sklearn.metrics import auc


def plot_ROC(fpr, tpr, auc):
    plt.style.use('seaborn-notebook')
    plt.figure(figsize=(10,7), dpi=80)
    plt.plot([0, 1], [0, 1], 'k--')
    plt.plot(fpr, tpr)
    plt.title('LOF ROC without Cover Traffic (AUC = {:.3f})'.format(auc), fontsize=22)
    plt.xlabel('False positive rate', fontsize=16)
    plt.ylabel('True positive rate', fontsize=16)
    plt.show()

# Function that evaluates the AE performance. y_true is the true label (0\1), gaps is the AE_gaps
def evaluate_method(y_true, gaps):
    y_true = np.array(list(map(int, y_true)))
    gaps = np.array(gaps)
    
    roc_fpr, roc_tpr, roc_th = roc_curve(y_true, gaps)

    auc = roc_auc_score(y_true, gaps)

    plot_ROC(roc_fpr, roc_tpr, auc)

    return roc_auc_score(y_true, gaps), roc_fpr, roc_tpr, roc_th

# Function that removes the first line of a CSV and write the new one to temp.csv
def remove_first_csv_line(file_path):
    with open(file_path,'r') as f:
        with open(TEMP_PATH,'w') as f1:
            next(f) # skip header line
            for line in f:
                f1.write(line)

# shuffle the mini flows by serial number (as groups)
def shuffle_mini_flows(file_path):
    with open(file_path, 'r') as fin:
        reader = csv.reader(fin, lineterminator='\n')

        # Get distinct serial nums
        serial_nums = []
        for row in reader:
            serial_nums.append(row[0])
        serial_nums = list(dict.fromkeys(serial_nums))

    # For unsupervised case - remove mal serials from serial list
    mal_serials = []
    beg_serials = []
    for serial in serial_nums:
        if float(serial) > 91:
            mal_serials.append(serial)
        else:
            beg_serials.append(serial)
    
    # Shuffle the serial nums
    random.shuffle(beg_serials)

    # divide the serial nums to train and test set
    train_set_serials = beg_serials[0:int(len(beg_serials) * 0.7)]
    test_set_serials = beg_serials[len(train_set_serials):]
    test_set_serials = test_set_serials + mal_serials
  
    train_set = []
    test_set = []

    # Divide the data to train and test sets according to the serial nums
    with open(file_path, 'r') as fin:
        reader = csv.reader(fin, lineterminator='\n')
        
        found_flag = 0
        for row in reader:
            found_flag = 0
            for i in train_set_serials:
                if row[0] == i:
                    train_set.append(row)
                    found_flag = 1
                    break
            
            if found_flag == 1:
                continue

            for j in test_set_serials:
                if row[0] == j:
                    test_set.append(row)
                    break
    
    return train_set, test_set


def identify_mal_flows(X_test_with_label, pred):
    # Get flows serials-label dict (not mini flows)
    flow_serials = {}
    for i in range(len(pred)):
        uniq_serial = X_test_with_label[i,0].split(".")[0]
        uniq_label = X_test_with_label[i,LABEL_INDEX]
        if uniq_serial not in flow_serials:
            flow_serials[uniq_serial] = uniq_label

    # Get anomalous mini-flow count per serial number (also all mini flows per flow)
    mini_flow_anom_count = {}
    mini_flow_count = {}
    for i in range(len(pred)):
        uniq_serial = X_test_with_label[i,0].split(".")[0]
        if uniq_serial in mini_flow_count:
            mini_flow_count[uniq_serial] += 1
        else:
            mini_flow_count[uniq_serial] = 1

        if str(pred[i]) == '-1':
            if uniq_serial in mini_flow_anom_count:
                mini_flow_anom_count[uniq_serial] += 1
            else:
                mini_flow_anom_count[uniq_serial] = 1

    # Decide if flow is anomalous according to MINI_FLOW_THRESHOLD (count of mini flows)
    real_anom_flows = []
    pred_anom_flows = []
    for key, value in flow_serials.items():
        if '1' == value:
            real_anom_flows.append(key)
    
    for key, value in mini_flow_anom_count.items():
        print("Flow ", key, "with ", value, "mini flows out of ", mini_flow_count[key])
        if value/mini_flow_count[key] > MINI_FLOW_THRESHOLD:# and mini_flow_count[key] > 50:
            pred_anom_flows.append(key)
        # if value > MINI_FLOW_THRESHOLD:
        #     pred_anom_flows.append(key)

    print("Real anomalous flows: ", real_anom_flows)
    print("Predicted anomalous flows: ", pred_anom_flows)
    TP = 0
    FP = 0
    FN = 0
    for p in pred_anom_flows:
        if p in real_anom_flows:
            TP += 1
        else:
            FP += 1
    for r in real_anom_flows:
        if r not in pred_anom_flows:
            FN += 1
    print("TP = ", TP, ", FP = ", FP, ", FN = ", FN)
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    F1_score = 2 * (precision * recall) / (precision + recall)
    print("F1 score: ", F1_score)

    return F1_score

# If the sklearn fails, maybe it's because there are faulty lines (with no values or NaN). this func prints the bad lines
def print_bad_rows(X_train_no_label):
    df_x = pd.DataFrame(X_train_no_label)
    df_x = df_x.apply(pd.to_numeric, errors='coerce')
    is_NaN = df_x.isnull()
    row_has_NaN = is_NaN.any(axis=1)
    rows_with_NaN = df_x[row_has_NaN]
    print(rows_with_NaN)

def find_optimal_cutoff(fpr, tpr, threshold):
    i = np.arange(len(tpr))
    roc = pd.DataFrame({'tf' : pd.Series(tpr-(1-fpr), index=i), 'threshold' : pd.Series(threshold, index=i)})
    roc_t = roc.iloc[(roc.tf-0).abs().argsort()[:1]]

    return list(roc_t['threshold'])


# This script should identify CRCC\Wifi Microjamming attacks using Deep AE on mini-flows.

# CONSTS
ATTACK_TYPE = "WIFI_MICROJAM" # can be CRCC or WIFI_MICROJAM
TEMP_PATH = "/home/cc/orenGit/1_Data_collection/cross-router_CC/temp.csv" # arbitrary path

if ATTACK_TYPE == "CRCC":
    # INPUT_FILE_PATH = "/home/cc/orenGit/3_Real-time_network/crcc_features.csv"
    INPUT_FILE_PATH = "/home/cc/orenGit/1_Data_collection/cross-router_CC/mini_flow_size_data/split_1/full_1_split_rec_sen_mal_beg_features.csv"
    AE_GAP_THRESHOLD = 1 # 1 threshold of AE recontruction error that above it, the mini flow is considered anomalous (CRCC=1, small microjam=picks auto (later in code))
    MINI_FLOW_THRESHOLD = 0.02 # percent of anomalous mini flows to identify a flow as anomalous (CRCC=2% (10 in count), small microjam=50)
    LABEL_INDEX = 14
elif ATTACK_TYPE == "WIFI_MICROJAM":
    # INPUT_FILE_PATH = "/home/cc/orenGit/3_Real-time_network/microjam_features.csv"
    INPUT_FILE_PATH = "/home/cc/orenGit/2_Anomaly_detector/wifi_microjam/microjam_small_features_modified.csv"
    MINI_FLOW_THRESHOLD = 0.2 # percent of anomalous mini flows to identify a flow as anomalous (CRCC=4% (10 in count), small microjam=50)
    LABEL_INDEX = 14
else:
    print("Invalid attack type")
    exit(1)

# Remove feature headlines (output file in TEMP_PATH), get shuffled file path
remove_first_csv_line(INPUT_FILE_PATH)

# Shuffle the data & divide to train and test sets (with labels & MAC addresses)
X_train_full, X_test_full = shuffle_mini_flows(TEMP_PATH)
os.remove(TEMP_PATH)

# # Remove MAC addresses
X_train_with_label = np.delete(X_train_full, [1,2], axis=1)
X_test_with_label = np.delete(X_test_full, [1,2], axis=1)

# Get labels
Y_train = X_train_with_label[:,LABEL_INDEX]
Y_test = X_test_with_label[:,LABEL_INDEX]

# Remove labels
X_train_no_label = np.delete(X_train_with_label, LABEL_INDEX, axis=1)
X_test_no_label = np.delete(X_test_with_label, LABEL_INDEX, axis=1)

# Scale the features
scaler = MinMaxScaler()
X_train_no_label = scaler.fit_transform(X_train_no_label)
X_test_no_label = scaler.transform(X_test_no_label)

if ATTACK_TYPE == "CRCC":
    # Work with pandas dataframe from now on
    df_train = pd.DataFrame(X_train_no_label[:,1:])
    df_test = pd.DataFrame(X_test_no_label[:,1:])

    # Build the Auto Encoder neural network
    input_size = df_train.shape[1]
    main_input = Input((input_size, ))
    hidden = Dense(int(input_size*0.7), activation='tanh')(main_input)
    hidden = Dense(int(input_size*0.5), activation='tanh')(hidden)
    hidden = Dense(int(input_size*0.3), activation='tanh')(hidden)
    hidden = Dense(int(input_size*0.5), activation='tanh')(hidden)
    hidden = Dense(int(input_size*0.7), activation='tanh')(hidden)
    main_output = Dense(input_size, activation='sigmoid')(hidden)

    model = Model(inputs=main_input, outputs=main_output)
    model.compile(optimizer = 'rmsprop', loss = 'mse')
    model.summary()

    # Fit the AE to the train set (which has only normal mini flows)
    model.fit(df_train, df_train, batch_size=500, epochs=10, verbose=1)

    # Calculate the recontruction errors (or gaps) of the test set
    AE_gaps = np.linalg.norm(model.predict(df_test)-df_test, axis = 1)
    print("max:", max(AE_gaps), "min:", min(AE_gaps))

    # Evaluate the model's performance using ROC and AUC
    auc, fpr, tpr, th = evaluate_method(Y_test, AE_gaps)
    print("AUC: " + str(auc))

    # Label a mini flow as anomalous if the AE gap is bigger 1
    pred_anom_index = []
    pred = []

    # AE_GAP_THRESHOLD = find_optimal_cutoff(fpr,tpr,th)
    for i in range(len(AE_gaps)):
        if AE_gaps[i] > AE_GAP_THRESHOLD:
            pred_anom_index.append(i)
            pred.append(-1)
        else:
            pred.append(1)

    # Compare the AE prediction with the actual labels
    real_anom_index = np.where(X_test_with_label[:,LABEL_INDEX] == '1')

    score = 0
    fp_score = 0

    for ind in pred_anom_index:
        if ind in real_anom_index[0]:
            score += 1
        else:
            fp_score += 1

    print("Total: ", len(pred_anom_index))
    print("TP: ", score, "\\", real_anom_index[0].size, ", %TP: ", score/real_anom_index[0].size)
    print("FP: ", fp_score)

    pred_str = []
    for i in range(len(pred)):
        if pred[i] == -1:
            pred_str.append('0')
        else:
            pred_str.append('1')

    mini_flow_f1_score = f1_score(Y_test, pred_str, pos_label='1')

    # Identify the malicious flows by counting mini flows (using MINI_FLOW_THRESHOLD)
    flow_f1_score = identify_mal_flows(X_test_with_label, pred)

else:
    clf = LocalOutlierFactor(novelty=True, n_neighbors=20)
    clf.fit(X_train_no_label[:,1:]) # fit without serial number
    pred = clf.predict(X_test_no_label[:,1:]) # predict without serial number
    scoring = -clf.decision_function(X_test_no_label[:,1:])
    int_y_test = []
    for y in Y_test:
        if y == '1':
            int_y_test.append(1)
        else:
            int_y_test.append(-1)
    fpr, tpr, thr = roc_curve(int_y_test, scoring)
    auc_lof = auc(fpr,tpr)
    plot_ROC(fpr, tpr, auc_lof)

    # Evaluate the identifier's performance
    pred_anom_index = np.where(pred == -1)
    real_anom_index = np.where(X_test_with_label[:,LABEL_INDEX] == '1')
    
    score = 0
    fp_score = 0

    for ind in pred_anom_index[0]:
        if ind in real_anom_index[0]:
            score += 1
        else:
            fp_score += 1
    
    print("Total anomalies: ", pred_anom_index[0].size)
    print("TP: ", score, "\\", real_anom_index[0].size, ", %TP: ", score/real_anom_index[0].size)
    print("FP: ", fp_score)

    try:
        flow_f1_score = identify_mal_flows(X_test_with_label, pred)
    except:
        flow_f1_score = 0
    pred_str = []
    for p in pred:
        if p == -1:
            pred_str.append('1')
        if p==1:
            pred_str.append('0')

    mini_flow_f1_score = f1_score(Y_test, pred_str, pos_label='1')
    print("Mini flows F1 score: ", mini_flow_f1_score)

f1_scores = [flow_f1_score, mini_flow_f1_score]

# Keep F1 score results
# with open(r'/home/cc/orenGit/3_Real-time_network/microjam_F1_scores.csv', 'a') as f:
#     writer = csv.writer(f)
#     writer.writerow(f1_scores)