from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebEngineWidgets import *
import sys
import base64
import requests

global safedomain
safedomain = 0
global dangerdomain
dangerdomain = 0


class BrowserWindow(QMainWindow):  # the main window class

    # create the QWeb engine
    def __init__(self, *args, **kwargs):
        super(BrowserWindow, self).__init__(*args, **kwargs)

        ############################ Create QWeb Item##########################
        self.browser = QWebEngineView()# creating a Q Web Engine View widget
        self.browser.setUrl(QUrl("http://google.co.uk"))  # sets google.co.uk into the url bar when the window is loaded
        # adding action when url get changed
        self.browser.urlChanged.connect(self.updateurlbaronclick)
        print("**")
        # adding action when loading is finished
        self.browser.loadFinished.connect(self.changetitle)
        self.setCentralWidget(self.browser)  # sets the browser as the main item in the window
        self.statusbar = QStatusBar()  # generates a status bar
        self.setStatusBar(self.statusbar)  # adds the status bar to the main window
        qtnav = QToolBar("Navigation")  # generates a QToolBar for navigation
        self.addToolBar(qtnav)  # this adds the tool bar to the main window

        ############################ Button Classes##########################
        back = QAction("Back", self)  # creates a button back to the previous page
        back.setStatusTip("To previous page")  # adds a tip to the button
        back.triggered.connect(self.browser.back)  # adds the back action
        qtnav.addAction(back)
        next = QAction("Forward", self)  # creates forward button
        next.setStatusTip("Forward to next page")
        next.triggered.connect(self.browser.forward)
        qtnav.addAction(next)
        refresh = QAction("Reload", self)  # creates a reload the page action
        refresh.setStatusTip("Reload page")
        refresh.triggered.connect(self.browser.reload)
        qtnav.addAction(refresh)
        home = QAction("Home", self)
        home.setStatusTip("Home")  # creates a button to naviagte back to the google url
        home.triggered.connect(self.gohome)
        qtnav.addAction(home)
        qtnav.addSeparator()  # adds separators to the task bar

        self.urlbar = QLineEdit()  # creates a url bar
        self.urlbar.returnPressed.connect(self.navigatetourlentered)  # adds the action for the url bar

        qtnav.addWidget(self.urlbar)  # adds it to the tool bar
        stop = QAction("Stop", self)  # creates a button to stop loading the page
        stop.setStatusTip("Stop loading the page") # Gives the action to the stop button
        stop.triggered.connect(self.browser.stop)  # stops the browser
        qtnav.addAction(stop)
        self.show()  # shows all the components

    def changetitle(self):
        title = self.browser.page().title()
        self.setWindowTitle("% s - MAWDT Safe Search" % title)  # sets the window title to MAWDT Safe Search

    def gohome(self):
        self.browser.setUrl(QUrl("http://www.google.co.uk/"))  # default to navigate to google

    # method called by the line edit when return key is pressed
    def navigatetourlentered(self):
        global safedomain
        global dangerdomain
        safe_file = "safedomain.txt"
        danger_file = "danger.txt"
        w = 0
        # getting url and converting it to QUrl object
        t = str(self.urlbar.text())
        print(t)
        # Take the first two // off the URL
        qt = t.split('/', 2)[2]
        gt = qt
        # count the number of / left in the URL
        rt = gt.count('/')
        jt = rt
        # Add one to the count to get the domain name and not the rest
        wt = jt + 1
        # Split the remaining / off the URLs
        bt = gt.split("/")[-wt]
        print("Domain", bt)
        with open(safe_file) as fp:  # enumerate through the hash file checking if there are any matches
            for sline in fp:
                if sline == bt + '\n':  # if the readable_hash of the file is equal to the hash in the file then preform the following
                    safedomain = 1
                    print("Domain has already been scanned")
        with open(danger_file) as dp:  # enumerate through the hash file checking if there are any matches
            for dline in dp:
                if dline == t + '\n':  # if the readable_hash of the file is equal to the hash in the file then preform the following
                    dangerdomain = 1
                    print("Domain is dangerous")
        if "https://www.google.co.uk/" in t:
            print("Not Searched")
            safedomain = 0
        elif "file///****" in t:
            print("Malicious Redirect")
        elif safedomain == 1:
            safedomain = 0
            print("No Scan Required")
            q = QUrl(self.urlbar.text())
        elif dangerdomain == 1:
            dangerdomain = 0
            print( "Dangerous Domain")
            q = QUrl("file///****")
        else:
            print("Domain requested, performing scan...")
            url_id = base64.urlsafe_b64encode(bt.encode()).decode().strip("=")
            print(url_id)
            url = "https://www.virustotal.com/api/v3/urls/" + url_id
            headers = {"Accept": "application/json",
                       "x-apikey": "41169e9801739d6d0fc5c9a4d643ea2e78161d6490c167ca240e6ba604ec4315"}
            reresponse = requests.request("GET", url, headers=headers)
            reresponsedata = reresponse.json()
            for key in reresponsedata['data']['attributes']['last_analysis_results']:
                print(key)
                print(' Detected: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['category'])
                print(' Result: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['result'])
                ify = reresponsedata['data']['attributes']['last_analysis_results'][key]['category']
                if ify == 'malicious':
                    w += 1
                print(' Update: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_name'])
                print('')
            q = QUrl(self.urlbar.text())
            if w > 5:
                q = QUrl("file///****")
                dangerdomain_file = open(danger_file, 'a+')
                dangerdomain_file.write(t + '\n')
            else:
                print("This is how many found it malicous", w)
                safedomain_file = open(safe_file, 'a+')
                safedomain_file.write(bt + '\n')

        print("This is how many found it malicous", w)
        print(q)

        # if url is scheme is blank
        if q.scheme() == "":
            # set url scheme to html
            q.setScheme("http")

        # set the url to the browser
        self.browser.setUrl(q)

    # method for updating url
    # this method is called by the QWebEngineView object
    def updateurlbaronclick(self, q):
        global safedomain
        global dangerdomain
        safe_file = "safedomain.txt"
        danger_file = "danger.txt"
        self.urlbar.setText(q.toString())
        w = 0
        # getting url and converting it to QUrl object
        q = QUrl(self.urlbar.text())
        t = str(self.urlbar.text())
        # Take the first two // off the URL
        qt = t.split('/', 2)[2]
        gt = qt
        # count the number of / left in the URL
        rt = gt.count('/')
        jt = rt
        print(jt)
        # Add one to the count to get the domain name and not the rest
        wt = jt + 1
        # Split the remaining / off the URLs
        bt = gt.split("/")[-wt]
        print("Domain")
        print(bt)
        with open(safe_file) as fp:  # enumerate through the hash file checking if there are any matches
            for sline in fp:
                if sline == bt + '\n':  # if the readable_hash of the file is equal to the hash in the file then preform the following
                    safedomain = 1
                    print("Domain has already been scanned")
        with open(danger_file) as dp:  # enumerate through the hash file checking if there are any matches
            for dline in dp:
                if dline == bt + '\n':  # if the readable_hash of the file is equal to the hash in the file then preform the following
                    dangerdomain = 1
                    print("Domain is dangerous")
        print("Search URL:", t)
        # Do not perform a API request if it is on the Google domain
        if "https://www.google.co.uk/" in t:
            print("Not Searched")
            safedomain = 0
        # Do not perform a API request if it is on the safe redirect page
        elif "file///****" in t:
            print("Malicious Redirect")
        elif safedomain == 1: # if domain is in safe file the dont scan it
            safedomain = 0
            print("No Scan Required")
            q = QUrl(self.urlbar.text())
        elif dangerdomain == 1: # if domain is in danger file redirect immediately
            dangerdomain = 0
            print( "Dangerous Domain")
            q = QUrl("file///****")
        else:
            # Generate the base 64 unique identifier of the inputted URL
            url_id = base64.urlsafe_b64encode(bt.encode()).decode().strip("=")
            print(url_id)
            # URL the API request is being sent to
            url = "https://www.virustotal.com/api/v3/urls/" + url_id
            # API request headers
            headers = {"Accept": "application/json",
                       "x-apikey": "41169e9801739d6d0fc5c9a4d643ea2e78161d6490c167ca240e6ba604ec4315"}
            reresponse = requests.request("GET", url, headers=headers)
            reresponsedata = reresponse.json()
            # print the result of each virus engine one by one looping through using the engine name as the identifier
            for key in reresponsedata['data']['attributes']['last_analysis_results']:
                print(key)
                print(' Detected: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['category'])
                print(' Result: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['result'])
                ify = reresponsedata['data']['attributes']['last_analysis_results'][key]['category']
                if ify == 'malicious':
                    w += 1
                print(' Update: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_name'])
                print('')
                # if the result is malicious then increase the w counter by one
                # if more than one virus engine comes back as positive then redirect
            if w > 5:
                q = QUrl("file///****")
                dangerdomain_file = open(danger_file, 'a+')
                dangerdomain_file.write(t + '\n')
            else:
                print("This is how many found it malicous", w)
                safedomain_file = open(safe_file, 'a+')
                safedomain_file.write(bt + '\n')

        print(w)

        # if url is scheme is blank
        if q.scheme() == "":
            # set url scheme to html
            q.setScheme("http")

        # set the url to the browser
        self.browser.setUrl(q)

        self.urlbar.setText(q.toString())

        # setting cursor position of the url bar
        self.urlbar.setCursorPosition(0)


pyqt5app = QApplication(sys.argv)  # creates the pyQt5 application

pyqt5app.setApplicationName("MAWDT Safe Search")  # sets the name of the application

applicationwindow = BrowserWindow()  # creates a main window item

pyqt5app.exec_()  # loops the file
