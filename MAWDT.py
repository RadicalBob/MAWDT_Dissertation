from __future__ import print_function
from tkinter import *
from tkinter import ttk
import json
import requests
import hashlib
import time
import os
import shutil
import glob
import tkinter as tk

pathdls = ('C:/') # download direcotry path
patheml = ('C:/') # email directory path

global e
e = []
global dls1
dls1 = []

global dl2
dls2 = []

global eml1
eml1 = []

global eml2
eml2 = []
global runnum
runnum = 0

global safehashinfile
safehashinfile = 0

global confirmdelete
confirmdelete = 0

global file_countdls
file_countdls = 0

global file_counteml
file_counteml = 0

global rescanid
rescanid = ""

global basename
basename = ""

global hashinfile
hashinfile = 0
global initalscannum
initalscannum = 0

global malhash
malhash = ""

global File_Name
File_Name = ""

global readable_hash
readable_hash = ""

global dir_list
dir_listdls = []
dir_listdls = os.listdir(pathdls)

dir_listeml = []
dir_listeml = os.listdir(patheml)

global x
x = []

global fileneedsdel
fileneedsdel = 0

global filedelpath
filedelpath = []

global z
z = 0

global FileName
FileName = []

API_KEY = ''
#
def filescan(): # performs a VirusTotal scan of the file then takes a decision based on the results
    global basename # import the basename variable
    global readable_hash # import the readable_hash variable
    global File_Name # import the File_Name variable
    global FileName # import the FileName variable
    global z # import the z variable
    global hashinfile # import the hashinfile variable
    global filedelpath # import the filedelpath variable
    hashinfile = 0
    f = open(readable_hash + ".txt", "a+") # create a new file with the name of the hash
    f.write("Report For File:"+File_Name+'\n'+'\n'+"***************************" + '\n'+ "Virus Engine Results"+'\n'+"***************************"+'\n'+'\n') # write a header into the file
    print(File_Name)
    print(readable_hash)
    url = "https://www.virustotal.com/api/v3/files/"+readable_hash
    headers = {"Accept": "application/json","x-apikey": "9affb4f33224e6af69ee5b1517d95a847132ba7c41851ac0603f8a9a279c0f2a"}
    response = requests.request("GET", url, headers=headers)
    print(response)
    iniresponse = requests.request("GET", url, headers=headers)
    reresponsedata = iniresponse.json()
    if response.status_code == 200: # if the API request is successful then perform a for loop on the results
        for key in reresponsedata['data']['attributes']['last_analysis_results']: # navigate to the data within these fields
            print(key)
            f = open(readable_hash+".txt", "a+")
            f.write(str(key) + '\n')
            x1 = (' Detected: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['category']) # paste the category into the file
            f = open(readable_hash+".txt", "a+")
            f.write(str(x1) + '\n')
            print(' Detected: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['category'])
            ifd = reresponsedata['data']['attributes']['last_analysis_results'][key]['category']
            x2 = (' Version: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_version']) # paste the engine version into the file
            f = open(readable_hash + ".txt", "a+")
            f.write(str(x2) + '\n')
            print(' Version: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_version'])
            x3 = (' Update: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_update']) # paste the engine update into the file
            f = open(readable_hash + ".txt", "a+")
            f.write(str(x3) + '\n')
            print(' Update: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['engine_update'])
            x4 = (' Result: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['result']) # past the results into the file
            f = open(readable_hash + ".txt", "a+")
            f.write(str(x4) + '\n'+'\n')
            f.close()
            print(' Result: ', reresponsedata['data']['attributes']['last_analysis_results'][key]['result'])
            print('')
            if ifd == 'malicious': # if the result is malicious then increment the initialscannum counter by 1
                global initalscannum
                initalscannum += 1
    else:
        print("File is not in database, move onto next file") # if the API responds with a code other than 200 then print error and proceed to the next file
        initalscannum = 0

    f = open(readable_hash + ".txt", "a+")
    f.write('\n'+'\n'+"***********************" + '\n'+ "The inital scan of this file shows that " + (str(initalscannum)) + " engines find it malicious" +'\n' + "***********************" + '\n'+'\n') # paste the results number into the file
    f.close
    print(initalscannum,"/64")
    if initalscannum >= 5: # if the scan number is greater than 5 then perform the following actions
        z += 1
        os.makedirs("C://quarantine" + str(readable_hash)) # make a new directory on the desktop which is called "quarantine" + the hash of the file
        if ".docx" in basename:
            os.system("taskkill /f /im winword.exe")  # if basename includes .docx then kill the winword.exe program
        if ".xls" in basename:
            os.system("taskkill /f /im EXCEL.exe")  # if basename includes .xls then kill the EXCEL.exe program
        if ".ppt" in basename:
            os.system("taskkill /f /im powerpnt.exe")  # if basename includes .ppt then kill the powerpnt.exe program
        if ".pdf" in basename:
            os.system("taskkill /f /im firefox.exe")  # if basename includes .pdf then kill the firefox.exe program
        if ".pdf" in basename:
            os.system("taskkill /f /im chrome.exe")  # if basename includes .pdf then kill the chrome.exe program
        if ".pdf" in basename:
            os.system("taskkill /f /im msedge.exe")  # if basename includes .pdf then kill the msedge.exe program
        if ".txt" in basename:
            os.system("taskkill /f /im notepad.exe")  # if basename includes .txt then kill the notepad.exe program
        if ".exe" in basename:
            os.system("taskkill /f /im " + basename)  # if basename includes .exe then kill the basename program
        print(File_Name)
        shutil.move(basename, "C://quarantine" + str(readable_hash)) # move the malicious file to the new quarantine directory
        filedelpath = "C://quarantine" + str(readable_hash) + "/" + FileName
        f= open(readable_hash + ".txt", "a+")
        f.write("***********************ALERT***********************"+ '\n')
        f.write("Due to the number of positive identifications on this file it has been closed and moved to a quarantine location at:" + '\n' + filedelpath + "***********************")
        f.close
        global malhash
        malhash = readable_hash
        text_file = "hash.txt"
        keyword_file = open(text_file,'a+')
        keyword_file.write(str(malhash) + '\n')
        sendrescanrequest() # request a rescan on the file
    elif initalscannum < 5 and response.status_code == 200: # if the positive id number is less than 5 then proceed to the next file
        txt_file = "safehash.txt"
        safekeyword_file = open(txt_file, 'a+')
        safekeyword_file.write(str(readable_hash) + '\n')
        initalscannum = 0
    elif response.status_code != 200:
        initalscannum = 0

def sendrescanrequest():
    initalscannum = 0
    url = "https://www.virustotal.com/api/v3/files/" + malhash + "/analyse"
    headers = {"Accept": "application/json",
               "x-apikey": "9affb4f33224e6af69ee5b1517d95a847132ba7c41851ac0603f8a9a279c0f2a"} # send API call to request a new scan of the file
    response = requests.request("POST", url, headers=headers)
    responsedata = response.json()
    data = None
    with open('id.json', 'w') as f: # paste the contents of the response into the id.json file
        json.dump(responsedata, f)
    with open('id.json') as f: # load the contents of the id.json file
        data = json.load(f)
    with open('id.json') as file: # search for the identifier id within the file
        contents = file.read()
        search_word = "id"
        if search_word in contents:
            print('Rescan id is')
            yaraid = (data['data']['id']) # search for the identifier id within the file
            global rescanid
            rescanid = yaraid # save the id to the rescanid global variable
            print(yaraid)
            print(rescanid)
            getnewscanresultsdownload() # proceed to the getnewscanresultsdownload() function


def getnewscanresultsdownload(): # this function sends the id from the sendrescanrequestdownload function in order to get the new scan data
    global fileneedsdel # import the fileneedsdel variable
    global filedelpath # import the filedelpath variable
    initalscannum = 0
    t = 0
    url = "https://www.virustotal.com/api/v3/analyses/" + rescanid
    headers = {"Accept": "application/json",
               "x-apikey": "9affb4f33224e6af69ee5b1517d95a847132ba7c41851ac0603f8a9a279c0f2a"}
    reresponse = requests.request("GET", url, headers=headers)
    reresponsedata = reresponse.json()
    if reresponse.status_code == 200 and reresponsedata['data']['attributes']['status'] == 'queued':
        print("The scan is queued, please wait...")
        time.sleep(60)
        getnewscanresultsdownload()
    else:
        for key in reresponsedata['data']['attributes']['results']:
            print(key)
            print(' Detected: ', reresponsedata['data']['attributes']['results'][key]['category'])
            ify = reresponsedata['data']['attributes']['results'][key]['category']
            print(' Version: ', reresponsedata['data']['attributes']['results'][key]['engine_version'])
            print(' Update: ', reresponsedata['data']['attributes']['results'][key]['engine_update'])
            print(' Result: ', reresponsedata['data']['attributes']['results'][key]['result'])
            print('')
            if ify == 'malicious':
                t += 1
    print(t)
    if t > 5:
        print("This file is confirmed as malicious")
        fileneedsdel = 1


def browserrun():
    os.system('webbrowser.py') # run the web browser

def hashcheck():
    global fileneedsdel  # import the fileneedsdel variable
    global filedelpath  # import the filedelpath variable
    global safehashinfile
    global readable_hash # import the readable_hash variable
    global File_Name # import the File_Name variable
    global FileName
    global hashinfile # import the hashinfile variable
    global basename # import the basename variable
    print("Basename", basename)
    text_file = "hash.txt"
    txt_file = "safehash.txt"
    keyword_file = open(text_file) # open the hash text file
    j = keyword_file.readlines()
    with open(txt_file) as fp: # enumerate through the hash file checking if there are any matches
        for sline in fp:
            if sline == readable_hash + '\n': # if the readable_hash of the file is equal to the hash in the file then preform the following
                safehashinfile = 1
    with open(text_file) as fp: # enumerate through the hash file checking if there are any matches
        for line in fp:
            if line == readable_hash + '\n': # if the readable_hash of the file is equal to the hash in the file then preform the following
                hashinfile = 1
                print("Match in the file")
                if ".docx" in basename:
                    os.system("taskkill /f /im winword.exe") # if basename includes .docx then kill the winword.exe program
                if ".xls" in basename:
                    os.system("taskkill /f /im EXCEL.exe") # if basename includes .xls then kill the EXCEL.exe program
                if ".ppt" in basename:
                    os.system("taskkill /f /im powerpnt.exe") # if basename includes .ppt then kill the powerpnt.exe program
                if ".pdf" in basename:
                    os.system("taskkill /f /im firefox.exe") # if basename includes .pdf then kill the firefox.exe program
                if ".pdf" in basename:
                    os.system("taskkill /f /im chrome.exe") # if basename includes .pdf then kill the chrome.exe program
                if ".pdf" in basename:
                    os.system("taskkill /f /im msedge.exe") # if basename includes .pdf then kill the msedge.exe program
                if ".txt" in basename:
                    os.system("taskkill /f /im notepad.exe") # if basename includes .txt then kill the notepad.exe program
                if ".jpg" in basename:
                    os.system("taskkill /f /im Microsoft.Photos.exe") # if basename includes .jpg then kill the Microsoft.Photos.exe program
                if ".png" in basename:
                    os.system("taskkill /f /im Microsoft.Photos.exe") # if basename includes .png then kill the Microsoft.Photos.exe program
                if ".exe" in basename:
                    os.system("taskkill /f /im " + basename) # if basename includes .exe then kill the basename program
                os.makedirs("C://quarantine" + str(readable_hash)) # make a new directory on the desktop which is called "quarantine" + the hash of the file
                shutil.move(basename, "C://quarantine" + str(readable_hash)) # move the malicious file to the new quarantine directory
                filedelpath = "C:/Users/islan/OneDrive/Desktop/quarantine" + str(readable_hash) + "/" + FileName
                f = open('hash.txt', 'r') # open the hash txt file
                line_num = 0 # set line number to 0
                search_phrase = readable_hash
                for line in f.readlines(): # enumerate through the file until the readable hash is found, increasing the counter by one each time
                    line_num += 1
                    if line.find(search_phrase) >= 0:
                        print("Found at line", line_num) # print the line which the hash was found at.
    print("Is hash in custom file?:", hashinfile)
    time.sleep(3)
    if hashinfile == 1:
        fileneedsdel = 1
    elif safehashinfile == 1:
        print("File Has Been Scanned Already, Not Malicious")
        safehashinfile = 0
    elif hashinfile == 0 and safehashinfile != 1: # if the hash is not in the file then continue to the scan function
        print("Hash not in file, the file will now be scanned")
        filescan()




def secondcheckdls():  # this function is operated when a new file appear in the download directory
    global dls1 # import the dls1 variable
    global dls2 # import the dsl 2 variable
    global x # import the x variable
    global dir_listdls # import the dir_listdls vriable
    global runnum # import the runnum variable
    global readable_hash # import the readable_hash variable
    global basename # import the basename variable
    print(dir_listdls)
    for root, dirs, files in os.walk(r'C:\\Downloads', topdown=True): #Downloads Folder
        for name in files: # enumerate through the file and check each item if has been scanned before
            file_count2 = sum(len(files) for _, _, files in os.walk(r'C:\\Downloads')) # Downloads Folder
            print(file_count2)
            print(os.path.join(root, name))
            FileName = (os.path.join(name))
            basename = (os.path.join(root, name))
            print("BASENAME", basename) # print the basename of the file, this is just the file name followed by the extension
            print(FileName)
            print(dir_listdls)
            if FileName in x:
                print("File Has Already Been Scanned") # if the file name is in the x list then it has already been scanned
                continue

            if FileName in dls1 or dls2: # if the file is in dls1 or dls2 then it is a JPG or PNG and should not be scannned
                print("File is a JPG or PNG")

            if ".part" in FileName: # if the file name has .part in it it means that it is currently downloading. The program should wait 30 seconds then try again
                print("WAITING")
                if FileName in x:
                    time.sleep(30) # wait 30 seconds
                    my_mainloop() # go back to the main loop to check if the new file has been downloaded
                else:
                    x.append(FileName)
                    time.sleep(30) # wait 30 seconds
                    my_mainloop() # go back to the main loop to check if the new file has been downloaded

            else: # For all other files proceed with a scan
                print(x)
                print("A New File Hash Appeared in the folder")
                print(FileName)
                hasher = hashlib.md5()
                with open('C://Downloads/' + (str(FileName)), 'rb') as f:
                    bytes = f.read()  # read file as bytes
                    readable_hash = hashlib.md5(bytes).hexdigest(); # save the md5 hash of the file to the readable_hash variable
                    print("The Hash of The File Is:",readable_hash)
                    hashcheck() # proceed to the first file check
                    initalscannum = 0
                    print("")
                    x.append(FileName)
    dir_listdls = os.listdir(pathdls)
    print("File Scan Complete")

def secondcheckeml(): # this function is operated when a new file appear in the email directory
    global e # import the e variable
    global dir_listeml # import the dir_listeml variable
    global runnum # import the runnum variable
    global readable_hash # import the readable_hash
    global basename # import the base name variable
    global eml1 #import the eml1 variable
    global eml2 # import the eml2 variable
    print(dir_listeml)
    for root, dirs, files in os.walk("C:", topdown=True): #email folder
        for name in files: # loop through each file in the list and perform a check on it
            file_count2 = sum(len(files) for _, _, files in os.walk("C:")) #email folder
            print(file_count2)
            print(os.path.join(root, name))
            FileName = (os.path.join(name))
            basename = (os.path.join(root, name))
            print("BASENAME", basename) # print the basename of the file, this is just the file name followed by the extension
            print(FileName)
            print(dir_listeml)
            if FileName in e:
                print("File Has Already Been Scanned")
                continue

            if FileName in eml1 or eml2:
                print("File is either JPG or PNG")

            else: # this option is for when a new file appears which is not a jpg or png
                print(e)
                print("A New File Hash Appeared in the folder")
                print(FileName)
                hasher = hashlib.md5()
                with open('C:' + (str(FileName)), 'rb') as f: # email folder
                    bytes = f.read()  # read file as bytes
                    readable_hash = hashlib.md5(bytes).hexdigest(); # create a md5 hash of the file
                    print("The Hash of The File Is:",readable_hash)
                    f.close()
                    hashcheck() # go to the first scan function
                    initalscannum = 0
                    print("")
                    e.append(FileName) # once the scan is complete then append the File Name to the e list to prevent it from being scanned again
    dir_listdls = os.listdir(pathdls)
    print("File Scan Complete")

######### Program Start ############
# pip install pyfiglet
from pyfiglet import Figlet

custom_fig = Figlet(font='big')
print(custom_fig.renderText('MAWDT'))
time.sleep(10)
# prints directory names
print("Files and directories in '", pathdls, "' :")
print("Files and directories in '", patheml, "' :")

# prints all files
print("Directory List:", dir_listdls)
print("Directory List:", dir_listeml)

file_countdls = sum(len(files) for _, _, files in os.walk('C://Downloads')) # takes a file count of the download directory
print("File Count:",file_countdls)

os.chdir('C://Downloads') #download directory

os.chdir('C:/') #change user desktop


for root, dirs, files in os.walk('C://Downloads', topdown=True): #download directory
    for name in files: # loops through all files in the download directory and appends them to the x variable
        print("Full File Path", os.path.join(root, name))
        FileName = (os.path.join(name))
        x.append(FileName)
        basename = (os.path.join(root, name))
        print("BASENAME", basename)

while True:
    for root, dirs, files in os.walk('C://Downloads', topdown=True): #download directory
        for name in files:
            print("Full File Path", os.path.join(root, name))
            basename = (os.path.join(root, name))
            FileName = (os.path.join(name))
            if FileName in (dir_listdls) and runnum > 0: # if the file is in the directory list and the run number is greater than one then do not scan the file
                print("File has already been scanned")
                continue
            print(FileName)

            hasher = hashlib.md5()
            with open('C://Downloads/' + str(FileName), 'rb') as f: #download directory
                bytes = f.read()  # read file as bytes
                readable_hash = hashlib.md5(bytes).hexdigest();
                print("The Hash of The File Is:", readable_hash)
                f.close()
                hashcheck() # go to the first scan function
                initalscannum = 0
                print("")
    if runnum >0:
        break
    else:
        runnum +=1
    print("RUNNUM",runnum)
####################################

file_counteml = sum(len(files) for _, _, files in os.walk('C://')) # initial email file count email directory
print("File Count:",file_counteml)

os.chdir('C://') #email directory


os.chdir('C:/') # change to home directory
print("***EML1***",eml1)
print("***EML2***",eml2)
for root, dirs, files in os.walk('C:/', topdown=True): #email directory
    for name in files: # loops through all files in the email directory and appends them to the e variable
        FileName = (os.path.join(name))
        e.append(FileName)
        basename = (os.path.join(root, name))


for root, dirs, files in os.walk('C://', topdown=True): #email directory
    for name in files:
        print("Full File Path", os.path.join(root, name))
        FileName = (os.path.join(root, name))
        CheckName = (os.path.join(name))
        hasher = hashlib.md5()
        with open(str(FileName), 'rb') as f:
            bytes = f.read()  # read file as bytes
            readable_hash = hashlib.md5(bytes).hexdigest(); # create the md5 hash of the file
            print("The Hash of The File Is:", readable_hash)
            hashcheck() # go to the first scan function
            initalscannum = 0
            print("")

    if runnum > 2 :
        break
        print(runnum)
    else:
        runnum +=1
    print("RUNNUM",runnum)
##################################

def my_mainloop():
    global file_countdls
    global file_counteml
    print("IN THE LOOP")
    file_countdls2 = sum(len(files) for _, _, files in os.walk('C://Downloads')) # count the files in the download directory
    dir_listdls = os.listdir(pathdls) # save the download directory to the variable
    file_counteml2 = sum(len(files) for _, _, files in os.walk('C://')) # count the files in the email directory
    dir_listeml = os.listdir(patheml) # save the email directory to the variable
    dir_listdls.sort() # sorts the current download file list so it can be compared
    dir_listeml.sort() # sorts the current email file list so it can be compared
    x.sort() # sorts the initial download file list so it can be compared
    e.sort() # sorts the initial email file list so it can be compared
    print("The Initial Download File List Was:", x)
    print("The Current Download File List Is:", dir_listdls)
    print("The Initial Email File List Was:", e)
    print("The Current Email File List Is:", dir_listeml)
    if file_countdls2 > file_countdls or dir_listdls != x: # if the file count now is greater than the initial file count or the directory list now is not the same than the initial list then run secondcheck
        secondcheckdls()
    if file_counteml2 > file_counteml: # if the file count now is greater than the initial file count then run secondcheckeml
        secondcheckeml()
    if dir_listeml != e: # if the email directory now does not meet the email directory initially then run secondcheckeml
        secondcheckeml()
    print("Inital File Count:", file_countdls) # print the download file count when the software initially ran
    print("File Count Now:", file_countdls2) # print the current download file count
    print("Inital File Count:", file_counteml) # print the email file count when the software initially ran
    print("File Count Now:", file_counteml2) # print the current email file count
    print("No Changes, Monitoring Continues...")
    root.after(1, update) # switch to the update function

def deletefile():
    global filedelpath # import global variable filedelpath
    global fileneedsdel # import global variable fileneedsdel
    print(filedelpath)
    os.remove(filedelpath) # deletes the file stored in the file path filedelpath
    fileneedsdel = 0 # reset fileneedsdel to 0
    filedelpath = [] # reset filedelpath to empty
    update() # returns to the update loop

def deletefilechoice():
    global fileneedsdel # import global variable fileneedsdel
    global confirmdelete # import global variable confirmdelete
    root.geometry("860x77") # resize the tkinter window
    var = tk.IntVar()
    v.set("The file located in " + filedelpath + " is malicious and needs to be deleted, proceed?") # change the text of the v label
    button1 = tk.Button(root, text="Delete It", command=deletefile) # create a button and link it to delete file
    button1.place(x=335, y=50) # size the button
    button2 = tk.Button(root, text="Disregard", command=lambda: var.set(1)) # create a button to disregard the delete file prompt
    button2.place(x=400, y=50) # size the button
    print("waiting for input...")
    button2.wait_variable(var) # wait until an option has been clicked
    button1.destroy() # destroy button 1
    button2.destroy() # destroy button 2
    fileneedsdel = 0 # reset fileneedsdel to 0
    print("Input entered, proceeding")

def update():
    root.geometry("200x77") # resize the tkinter window
    v.set("Monitoring Continues") # updates the text label
    global fileneedsdel # import global variable fileneedsdel
    if fileneedsdel == 1: # if fileneedsdel has been set to 1 then run the deletefilechoice funtion
        deletefilechoice()
    root.after(1, my_mainloop) # after 1 second switch to the my_mainloop


root = tk.Tk()
button = ttk.Button(root, text="Web Browser", command=browserrun) # the button which opens the web browser
button.pack() # the position of the web browser button
v = StringVar()
Label(root, textvariable=v).pack() #creates a text label
root.geometry("200x77") # initial tkinter window size
root.after(1000, my_mainloop)
root.mainloop()

