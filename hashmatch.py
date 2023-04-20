#!/usr/bin/env python3

"""final vision is to use the hashtopolis api to query cracked creds from a set of hashes. 
Basically htp's hash search but usable as it can correlate.
input file is something like an unformatted ntds domain:uid:user:lm:nt, etc
output is all that + the plaintext"""

import os, json, ssl, time, sys, signal, requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class Hashmatch():

    def __init__(self):
        """stores apikey, and json queries for api calls"""
        self.version = "0.1"
        self.apikey = "YOUR API"
        self.dump_list = []
        self.credResult = []
        self.matchList = []
        self.cracked_hash_dir = './cracks'
        self.hash_file_dir = './hashes'
        self.match_file_dir = './matches'
        self.hashid = ""

        #json that doesnt need user input
        self.testconn = json.dumps({"section":"test","request":"connection"})
        self.testmykey = json.dumps({"section": "test","request": "access","accessKey": self.apikey})
        self.list_hashlists = json.dumps({"section": "hashlist","request": "listHashlists","accessKey": self.apikey})



    def check(self):
        """pre-checks before querying"""
        #check for local directories
        print('Checking for Directories')
        if not os.path.exists(self.hash_file_dir):
            os.makedirs(self.hash_file_dir)

        if not os.path.exists(self.cracked_hash_dir):
            os.makedirs(self.cracked_hash_dir)

        #test the server connection
        print('Checking your conection:\nResponse:')
        if not 'SUCCESS'.find(str(Hashmatch.send_request(self.testconn))):
            exit(0)
        
        #test your api key for validity
        print('Checking your API key:\nResponse:')
        if not 'ERROR'.find(str(Hashmatch.send_request(self.testmykey))):
            Hashmatch.clear()



    def clear(self):
        """clean up screen"""
        os.system('cls' if os.name == 'nt' else 'clear')


    def pickhashlist(self):
        """User interface for viewing hashlists, choosing one to compare to a local ntds"""
        print('Querying hashlists:\nResponse:')
        
        #query for all hashlists, need to add option for filtering
        hashlists = Hashmatch.send_request(self.list_hashlists)
        parsed = json.loads(hashlists)
        print(json.dumps(parsed, indent=4,sort_keys=True ))
        
        #user choosed the hashid they want to compare
        self.hashid = input('\nWhich hashlistId do you want to match to your NTDS? : \n')
        print('Obtaining cracked entries for hashlistId {}'.format(self.hashid))
        

        self.get_hashlist_info = json.dumps({"section": "hashlist","request": "getHashlist","hashlistId": self.hashid,"accessKey": self.apikey})

        #chosen hashid used to populate the json from __init__ section. does this even work?
        pickedhashlist = Hashmatch.send_request(self.get_hashlist_info)
        parsed = json.loads(pickedhashlist)
        print(json.dumps(parsed, indent=4,sort_keys=True ))



        self.export_cracked = json.dumps({"section": "hashlist","request": "getCracked","hashlistId": self.hashid,"accessKey": self.apikey})

        exportcracked = Hashmatch.send_request(self.export_cracked)
        parsed = json.loads(exportcracked)
        
        json_response = json.dumps(parsed, indent=4,sort_keys=True)

        print(json_response)

        #parse response
        response = json.loads(json_response)

        #just do this in memory? why write to a file
        f = open("./cracks/cracked.txt","w+")
        for i in response["cracked"]:
            cracked_hash = i["hash"]
            plaintext = i["plain"]
            #print('{}:{}'.format(cracked_hash, plaintext))
            f.write('{}:{}\n'.format(cracked_hash, plaintext))
        f.close()


    def wreck(self):
        #gross, needs cleaned up

        #open the cred file, ie the ntds dump
        for credFileName in os.listdir('./hashes/'):
                #open the file
                credFileOpen = open('./hashes/'+credFileName, "r")
                #for each line in opened file
                for line in credFileOpen:
                    #print(line)
                    #add to the dump dictionary
                    self.dump_list.append(line)

                
        #now that dump dict is populated, this section 'cracks' the hashes provided a pre-populated pot file
        #still in our lookup value iterate potfiles directory. you can have multiple pots, just in case
        for potFileName in os.listdir('./cracks/'):
            #open a pot file
            with open('./cracks/'+potFileName, 'r') as potFile:
                #then look at every line
                for potLine in potFile:
                    hash_to_search = potLine.split(':')[0].strip('\r\n')

                    #then for every line look at every line in the dump list
                    for i in self.dump_list:
                        if hash_to_search is not '':
                            #print('Looking for {} in {}'.format(hash_to_search, i))
                            if hash_to_search in i:
                                print('{}:{}'.format(i.strip('\r\n'),potLine.split(':')[1].strip('\r\n')))
                   


    def send_request(post_data):
        #ignore ssl errors
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        #record start time
        startTime=time.time()
        try:
            #uses http://docs.python-requests.org/en/master/api/
            response = requests.post("https://YOUR HASHTOPOLIS URL/api/user.php", post_data, verify=False)
        except requests.exceptions.RequestException as e:
            print(e)
            sys.exit(1)
        #record elapsed time
        elapsedTime = str(round((time.time()-startTime)*1000.0))
        '''print('\nPOST data {}'.format(post_data))
        print('\n____RESPONSE HEADERS____')
        for k in response.headers.items():
            print ('%s : %s' % (k[0], str(k[1].split(';'))))
        print('________________________\n\n')'''


        print('{} ms'.format(elapsedTime))
        return response.text


def main():
    run = Hashmatch()
    run.check()
    run.pickhashlist()
    run.wreck()

if __name__ == '__main__':
    main()

