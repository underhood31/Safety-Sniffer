import pickle as pk

class saveUrl:

    def __init__(self):
        self.allURLs=set()
        self.calls=0
        self.badURLs=set()
        mo=open("./Phish-Detection/model.bin","rb")
        v=open("./Phish-Detection/vectorizer.bin","rb")
        self.model=pk.load(mo)
        self.vectorizer=pk.load(v)
    def sniff(self,string):
        start=28
        end=-1
        for i in range(start,len(string)-1):
            if(string[i]==' ' and string[i+1]==' '):
                end=i
                break
        cur=string[start:end]
        # print(cur)
        self.allURLs.add(cur)
        ans=(self.model).predict(self.vectorizer.transform([cur]))
        if(ans[0]=='bad'):
            self.badURLs.add(cur)
        