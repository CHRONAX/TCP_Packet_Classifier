from re import sub
#from turtle import color
import streamlit as st
import pandas as pd
import numpy as np
import os
import boto3
import joblib
from sklearn.preprocessing import LabelEncoder
import altair as alt
from tabulate import tabulate
# import tempfile
# import shutil


# directory = "tempDir"
# parent ="TCP_Packet_Classifier"
# path = os.path.join(parent, directory)
# os.makedirs(path)

# DT_url="https://github.com/CHRONAX/TCP_Packet_Classifier/blob/daaa0e9ee3ea0fb788e354f5e25dbac194d57777/models/TCP_Decision_Tree_Classifier.pkl"
# KNN_url="https://github.com/CHRONAX/TCP_Packet_Classifier/blob/daaa0e9ee3ea0fb788e354f5e25dbac194d57777/models/TCP_KNN_Classifier.pkl"
# RF_url="https://github.com/CHRONAX/TCP_Packet_Classifier/blob/daaa0e9ee3ea0fb788e354f5e25dbac194d57777/models/TCP_RandomForest_Classifier.pkl"

#Naive_Baye_model= joblib.load(open('models/TCP_Naive_Baye_Classifier.pkl', 'rb'))
Decision_Tree_model= joblib.load(open('models/TCP_Decision_Tree_Classifier.pkl', 'rb'))
KNN_Classifier_model= joblib.load(open('models/TCP_KNN_Classifier.pkl', 'rb'))
#Logistic_Classifier_model= joblib.load(open('models/TCP_Logistic_Classifier.pkl', 'rb'))
#SVM_Classifier_model= joblib.load(open('models/TCP_SVM_Classifier.pkl', 'rb'))
RandomForest_Classifier_model= joblib.load(open('models/TCP_RandomForest_Classifier.pkl', 'rb'))

# st.sidebar.header('User Input Feature')
# select_model = ['Naive Baye', 'Decision Tree', 'K-Nearest Neighbor', 'Logistic Regresion', 'Select Vector Machine', 'Random Forest']
# selected_model = st.sidebar.selectbox('Model', select_model)

# fileitem = st.sidebar.file_uploader("Upload Pcap File")
# print(fileitem)

with open('style.css') as f:
    st.markdown(f'<style>{f.read()}<style>', unsafe_allow_html=True)


# @st.cache
# def convert_to_argus(fn):
#     #pcap_file_name= fn.name
#     # file_details = {"filename":pcap_file.name,"filetype":pcap_file.type,"filesize":pcap_file.size}
#     # print(file_details)
#     st.write(fn)
#     cmd = ["sudo", "argus", "-r", fn, "-w", "fn.argus"]
#     argus = subprocess.run(cmd, shell = True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
#     return argus

model_result_df = pd.DataFrame(
    [('Decision Tree', 0.9634680954700439, 0.96),
     ('K Nearest Neighbor', 0.9620068192888456, 0.96),
     ('Random Forest', 0.9634680954700439, 0.96)],
    columns=('model name', 'model accuracy', 'f1-score')
)




def convert_to_argus(fn):
    
    cmd = ["argus", "-r", fn, "-w", "fn.argus"]
    
    os.system("argus -r" + fn + " -w tempDir/fn.argus")
    
def color_row(row):
    value = row.loc['class']
    if value == 'anomaly':
        color == '#FFB3BA'
    else:
        color = '#BAFFC9'
    return ['background-color: {}'.format(color) for r in row]

    
    

    


def convert_to_csv(af):
    
    os.system("ra -r" + af + " -s dur proto flgs sbytes dbytes > tempDir/packetfile.csv")
    df = pd.read_csv("tempDir/packetfile.csv")
    df = pd.DataFrame(df)
    df['dur']=df['       Dur  Proto      Flgs     SrcBytes     DstBytes '].str.split('\t',expand=True)
    df['duration']=df['dur'].str.slice(stop=10)
    df['temp1']=df['dur'].str.slice(start=10)
    df['protocol_type']=df['temp1'].str.slice(stop=7)
    df['temp2']=df['dur'].str.slice(start=17)
    df['dst_bytes']=df['dur'].str.slice(start=40)
    df['temp3']=df['temp2'].str.slice(stop=31)
    df['src_bytes']=df['temp3'].str.slice(start=10)
    df['flag']=df['temp3'].str.slice(stop=10)
    df = df[['duration','src_bytes','dst_bytes','protocol_type','flag']]
    df=df.replace("[-*]","",regex=True)
    df.replace('',np.nan, inplace=True)
    df = df.dropna()
    df = df.loc[df['protocol_type'].isin(['    tcp'])]
    convert_dict = {'duration': float,
               'src_bytes': int,
               'dst_bytes': int}
    df = df.astype(convert_dict)
    encoder = LabelEncoder()

    # extract categorical attributes from both training and test sets 
    catdf = df.select_dtypes(include=['object']).copy()

    # encode the categorical attributes
    dfcat = catdf.apply(encoder.fit_transform)  
    df = df.drop(['protocol_type', 'flag'], axis=1)
    df = pd.concat([df,dfcat],axis=1)
    return df


def predict(fname,classification_model):
    
    if classification_model == "Decision_Tree":
        # DT_req = requests.get(DT_url)
        # with open("TCP_Decision_Tree_Classifier.pkl", "r") as f:
        #     f
        prediction = Decision_Tree_model.predict(fname)
    elif classification_model == "KNN_Classifier":
        # KNN_req = requests.get(KNN_url)
        # with open("TCP_KNN_Classifier.pkl", "r") as f:
        #     f
        prediction = KNN_Classifier_model.predict(fname)
    elif classification_model == "RandomForest_Classifier":
        # RF_req = requests.get(RF_url)
        # with open("TCP_RandomForest_Classifier.pkl", "r") as f:
        #     f
        prediction = RandomForest_Classifier_model.predict(fname)
    
    
    fname['class']=prediction
    return fname

# def send_plain_email(email_addr,result_anomaly, result_normal, result):
#     ses_client = boto3.client("ses", region_name="ap-northeast-1")
#     CHARSET = "UTF-8"

#     response = ses_client.send_email(
#         Destination={
#             "ToAddresses": [
#                 email_addr,
#             ],
#         },
#         Message={
#             "Body": {
#                 "Text": {
#                     "Charset": CHARSET,
#                     "Data": "Hello, world!" " \n " " There is possibly " + str(result_anomaly) + " anomalous TCP packets inside this pcap file.\n And " + str(result_normal) + " packets that are normal\n" + tabulate(result, headers = ['duration','src_bytes','dst_bytes','protocol_type','flag','class'], tablefmt = 'simple_grid'),
#                 }
#             },
#             "Subject": {
#                 "Charset": CHARSET,
#                 "Data": "Amazing Email Tutorial",
#             },
#         },
#         Source="0127701@kdu-online.com",
#     )
    
    

def send_html_email(email_addr,result_anomaly, result_normal, result):
    ses_client = boto3.client("ses", region_name="ap-northeast-1")
    CHARSET = "UTF-8"
    HTML_EMAIL_CONTENT ="<html>\n" \
        + "    <head></head>\n" \
        + "     <h1 style='text-align:center'>TCP Packet Analyzer Report</h1>\n" \
        + "     <p>" + tabulate(result, headers = ['duration','src_bytes','dst_bytes','protocol_type','flag','class'], tablefmt = 'html') + " </p>\n" \
        + "     <p> There is possibly " + str(result_anomaly) + " anomalous TCP packets inside this pcap file.\n  And " + str(result_normal) + " packets that are normal </p>\n" \
        + "</html>"
    
    
    

    response = ses_client.send_email(
        Destination={
            "ToAddresses": [
                email_addr,
            ],
        },
        Message={
            "Body": {
                "Html": {
                    "Charset": CHARSET,
                    "Data": HTML_EMAIL_CONTENT,
                }
            },
            "Subject": {
                "Charset": CHARSET,
                "Data": "TCP Packet Analyzer Report",
            },
        },
        Source="0127701@kdu-online.com",
    )



def main():
    
    st.title('TCP packet Classifier')

    st.sidebar.header('Model Selection')
    select_model = ['Decision_Tree', 'KNN_Classifier', 'RandomForest_Classifier']
    selected_model = st.sidebar.selectbox('1. Model', select_model)
    fileitem = st.sidebar.file_uploader("2. Upload Pcap File", type='pcap')
    print(fileitem)
    email = st.sidebar.text_input('3. Email Address(optional)', '')
    
    
    with st.expander("See model infos"):
        
        bar_chart1 = alt.Chart(model_result_df).mark_bar().encode(
            y='model accuracy',
            x='model name',
            color='model name'
        )
    
        bar_chart2 = alt.Chart(model_result_df).mark_bar().encode(
            y='f1-score',
            x='model name',
            color='model name'       
        )
        
        
        
        
        accuracy_tab, f1_tab = st.tabs(["📊 Model Accuracy" , "📊 F1-Score Description"])
        accuracy_tab.subheader("Model Accuracy")
        accuracy_tab.altair_chart(bar_chart1, use_container_width=True)
        
        f1_tab.subheader("Model f1-score")
        f1_tab.altair_chart(bar_chart2, use_container_width=True)
        
        #with accuracy_tab:
        st.header("Model Accuracy and F1-Score")
        model_result_df
        st.write("Based on the bar chart above, we can see that the performance of each models are significantly similar with come micro difference, \
                 the model has been tested with several pcap files, and the Decision Tree models comes out on top when tested against the other models.")
    
    



    if st.sidebar.button('Process'):
        st.header(selected_model)
        csv_file = 0
        prediction_result = 0
        
        # with tempfile.TemporaryDirectory(suffix='tempDir', dir='.') as tmpdir:
        #     tempfile.gettempdir()
            

        if fileitem is not None:
            
                                
            with open(os.path.join("tempDir",fileitem.name),"wb") as f:
                f.write(fileitem.getbuffer())
            
            file_path= "tempDir/"+fileitem.name
            convert_to_argus(file_path)
            
            
            file_path2= "tempDir/fn.argus"
            csv_file = (convert_to_csv(file_path2))

            prediction_result=(predict(csv_file,selected_model))
            
            prediction_result
            
            st.write(prediction_result['class'].value_counts())
            
            anomalies = prediction_result['class'].str.contains(r'anomaly').sum()
            normal = prediction_result['class'].str.contains(r'normal').sum()
            
            
                
            col1, col2 = st.columns(2)
            col1.metric("Normal", str(normal))
            col2.metric("Anomalies", str(anomalies))
            
            
            
            st.write("There are approximately " + str(anomalies) + " anomalous TCP packets inside this pcap file. And " + str(normal) + "  packets that are normal")
            
            rmfilepath1 = 'tempDir/packetfile.pcap'
            rmfilepath2 = 'tempDir/fn.argus'
            rmfilepath3 = 'tempDir/packetfile.csv'
            os.remove(rmfilepath1)
            os.remove(rmfilepath2)
            os.remove(rmfilepath3)
            #os.system("find . -type f -not -name 'README.txt'-delete")
            #shutil.rmtree(tmpdir)
            
        if email != "":
            send_html_email(email, anomalies, normal, prediction_result)
            st.subheader("Email sent successfully!")
            
            
            
            
            
            
            
        
    

    # fileitem = st.file_uploader("Upload Pcap File")
    # print(fileitem)

    




    # if fileitem is not None:
    #     fn = os.path.basename(fileitem)
    #     print(fn)
    #     //st.write(fn)

    #     flow = subprocess.run("sudo", "ra", "-r", fn, "-w", "fn.argus")
    #     print(flow)
    #     //st.write(flow)

    #     packet_file = subprocess.run("sudo", "ra", "-r", flow, "-s", "dur", "proto", "sbytes", "dbytes", ">" , "packetfile.csv")
    #     print(packet_file)
    #     //st.write(packet_file)




    # st.title('Classification Models')
    # if st.button('Naive Baye'):
    #     model = Naive_Baye_model
    #     print('hallo')

    # if st.button('Decision Tree'):
    #     model = Decision_Tree_Classifier_model
    #     print('halo')

    # if st.button('K-Nearest Neighbor'):
    #     model = KNN_Classifier_model
    #     print ('halo')

    # if st.button('Logistic Regression'):
    #     model = Logistic_Classifier_model
    #     print ('halo')

    # if st.button('Select Vector Machine'):
    #     model = SVM_Classifier_model
    #     print ('halo')

    # if st.button('Random Forest'):
    #     model = RandomForest_Classifier_model
    #     print ('halo')



if __name__=='__main__':
    main()






