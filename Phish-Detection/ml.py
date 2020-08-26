# This code has been written with reference from https://web.archive.org/web/20170514093208/http://fsecurify.com/using-machine-learning-detect-malicious-urls/

import pandas as pd
import numpy as np
import random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import pickle as pk
import re

def getTokens(input):
    tokensBySlash = re.split("/| ",str(input.encode('utf-8')))	#get tokens after splitting by slash or space
    allTokens = []
    for i in tokensBySlash:
        tokens = str(i).split('-')	#get tokens after splitting by dash
        tokensByDot = []
        for j in range(0,len(tokens)):
            tempTokens = str(tokens[j]).split('.')	#get tokens after splitting by dot
            tokensByDot = tokensByDot + tempTokens
        allTokens = allTokens + tokens + tokensByDot
    allTokens = list(set(allTokens))	#remove redundant tokens
    if 'com' in allTokens:
        allTokens.remove('com')	#removing .com since it occurs a lot of times and it should not be included in our feature
    return allTokens

def loadData(path):
    allurlscsv = pd.read_csv(path,',',error_bad_lines=False)	#reading file
    allurlsdata = pd.DataFrame(allurlscsv)	#converting to a dataframe
    
    allurlsdata = np.array(allurlsdata)	#converting it into an array
    random.shuffle(allurlsdata)	#shuffling
    return allurlsdata

def main():
    allurlsdata=loadData("./Data/data.csv")

    y = [d[1] for d in allurlsdata]	#all labels 
    corpus = [d[0] for d in allurlsdata]	#all urls corresponding to a label (either good or bad)
    vectorizer = TfidfVectorizer()	#get a vector for each url but use our customized tokenizer
    X = vectorizer.fit_transform(corpus) #get the X vector

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)	#split into training and testing set 80/20 ratio
    
    lgs = LogisticRegression()	#using logistic regression
    lgs.fit(X_train, y_train)
    print(lgs.score(X_test, y_test)) #pring the score. It comes out to be 98%
    fileV=open("vectorizer.bin","wb")
    fileM=open("model.bin","wb")
    pk.dump(lgs,fileM)
    pk.dump(vectorizer,fileV)

    X_predict = ['wikipedia.com','google.com/search=faizanahad','pakistanifacebookforever.com/getpassword.php/','www.radsport-voggel.de/wp-admin/includes/log.exe','ahrenhei.without-transfer.ru/nethost.exe','www.itidea.it/centroesteticosothys/img/_notes/gum.exe']
    X_predict = vectorizer.transform(X_predict)
    y_Predict = lgs.predict(X_predict)
    print(y_Predict) #printing predicted values


main()