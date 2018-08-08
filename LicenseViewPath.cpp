/** @file LicenseViewPath.cpp
 *  @purpose Verify the change in files
 *  and authentication of the module
 */

#include"LicenseViewPath.h"
using namespace std;

#define DELIM "."
#define DATA1 "uniqueHWId=sdfasdfasdf"
#define DATA "data='{\"filelist\":{\"key1\":\"val1\"}, \"licence\":\"sasdfbf\"}'"
#define SERVERRESPONSEURL "http://10.191.95.54/apis/fileResponse"
#define SERVERURL "http://10.191.95.54/apis/file"
#define TIMECHECK_H 15
#define TIMECHECK_M 13
#define RESPONSEMSG "\"success\":1"
#define SYSTEMWAIT 30

char* FilesVerification::responseString = NULL;

// Return 1 if string contain only digits, else return 0
int valid_digit(char *ip_str) {
    while (*ip_str) {
        if (*ip_str >= '0' && *ip_str <= '9') {
            ++ip_str;
        }
        else {
            return 0;
        }
    }
    return 1;
}

// Return 1 if IP string is valid, else return 0

int is_valid_ip(char *ip_str) {
    int i, num, dots = 0;
    char *ptr;
    string ip=ip_str;
    if (count(ip.begin(),ip.end(),'.')!=3)
    return 0;
    if(ip[0]=='0')
    return 0;
    for(char* it = ip_str; *it; ++it) {
    if(((*it)=='.')&&(((*(it+1))=='0')))
        return 0;}
    if (ip_str == NULL)
    return 0;
    ptr = strtok(ip_str, DELIM);
    if (ptr == NULL)
        return 0;
    while (ptr) {
        // After parsing string, it must contain only digits
        if (!valid_digit(ptr)) {
            return 0;
        }
        num = atoi(ptr);
        // Check for valid IP
        if (num >= 0 && num <= 255) {
            // Parse remaining string
            ptr = strtok(NULL, DELIM);
            if (ptr != NULL) {
                ++dots;
            }
        }
        else {
            return 0;
        }
    }
    // Valid IP string must contain 3 dots
    if (dots != 3) {
        return 0;
    }
    return 1;
}


/** @method parameterised constructor
 *  @purpose initialized the url
 */
FilesVerification::FilesVerification(char *url) {
    urlString = url;
    licenseKey = "";
    versionApp = "";
    uniqueHWId = "";
    validLicense = false;
    cout << "FilesVerification URL\t\t= " << url <<endl;
    if((url != NULL) && (is_valid_ip(url) == 1)) {
        cout << "FilesVerification Valid IP\t= " << urlString <<endl;
    }
    else {
        cout<<"InValid IP Address Please provide valid Server IP !!!"<<endl;
        exit(0);
    }
};

/** @function function_pt
 *  @purpose receive Json from NODE SERVER
 */
void FilesVerification::function_pt(void *ptr, unsigned int size, unsigned int nmemb) {
    responseString= new char;
    responseString=(char*)ptr;
    std::cout << "function_pt\t\t\t= "<<responseString<<endl;
};

/** @global Function webRequestResponse
 *  @purpose Send request to the server for data verification and get response of valid data
 *  @param char pointer to the url
 *  @return char pointer to the response
 */
char *webRequestResponse(char *url, const char *httpData) {
    cout << "WebRequestResponse_01\t\t= "<<url<<endl;
    cout<< "Data\t\t\t\t= " << httpData <<endl;
    // keeps the handle to the curl object
    CURL *curl_handle = NULL; // eg: "http://localhost:8080/caller/index.jsp"
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, DATA1);    //Json format : "HELLO=x&hello2=v"

    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, FilesVerification::function_pt);
    curl_easy_perform(curl_handle);
    curl_easy_cleanup(curl_handle);
    return "";
}

/** @method getFileListFromServer
 *  @purpose request the file list from the server for authenticate
 *  @param void
 *  @return void
 */
void FilesVerification::getFileListFromServer() {
    if(urlString != "") {
        //responseString = webRequestResponse((char *)urlString.c_str());
    }
    else {
    }
};

/** @method parseFileFromJson
 *  @purpose parse the response of the server
 *  @param void
 *  @return bool in-case file is invalid
 */
void FilesVerification::parseFileFromJson() {
    std::string strJson = responseString;
    Json::Value root;
    Json::Reader reader;
    // successful response from the server
    if(responseString != NULL) {
        bool parsingSuccessful = reader.parse(strJson.c_str(), root );     //parse process
        std::map<string, string> mymap;
        int i=0;
        for( Json::ValueIterator itr = root["data"].begin() ; itr != root["data"].end() ; itr++ ) {
                        sleep(1);
            std::cout << "--------------------------------------------------------\n";
            //cout<<itr.key().asString()<<"  :  ";
            //cout<<(root["data"][i])<<endl;
            const char *file = (root["data"][i]["path"].asString()).c_str();
            std::string transfer = md5_for_file(root["data"][i]["path"].asString());
            cout<<"file_name\t: "<<(root["data"][i]["file_name"])<<endl;
            cout<<"checksum\t: "<<(root["data"][i]["checksum"])<<endl;
            cout<<"path\t\t: "<<root["data"][i]["path"].asString()<<endl;
            cout<<"version\t\t: "<<(root["data"][i]["version"])<<endl;
            cout<<"customer_id\t: "<<(root["data"][i]["customer_id"])<<endl;
            printf("\t .----------------------.\n");
            if(root["data"][i]["checksum"] == transfer) {
                cout<<"\t|  MD5 MATCH : CONTINUE  |"<<endl;
                printf("\t '----------------------'\n");
                matchFound = true;
            }
            else{
                matchFound = false;
                cout<<"\t|  MD5 NOT MATCH  :   ABORT  |"<<endl;
                int x = system("sudo systemctl stop epic");
                printf("\t '----------------------'\n");
                break;
            }
            i++;
        }
               cout<<"parseFileFromJson 06"<<endl;
    }
}

/** @method fdGetFileSize
 *  @purpose get file size from the file descriptor
 *  @param int file descriptor
 *  @return long size of file
 */
long FilesVerification::fdGetFileSize(int fd) {
    struct stat stat_buf;
    int rc = fstat(fd, &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
};

/** @method md5_for_file
 *  @purpose generate md5 checksum value for the verification from the server
 *  @param char * filename for which md5 checksum value generate
 *  @return unsigned char * md5 checksum value
 */
std::string FilesVerification::md5_for_file(std::string filename) { //LicenseViewPath_BuildProcess
    int file_descript;
    unsigned long file_size;
    char *file_buffer;
    unsigned char *result = NULL;
    result = new unsigned char[(sizeof(*result) * MD5_DIGEST_LENGTH)];
    if (NULL == result) {
        printf("New failed\n");
    }
    printf("\t\tGENRATING MD5 VALUE\n");
    std::cout << "--------------------------------------------------------\n";
    std::cout <<"USING FILE :\t"<<filename.c_str()<<std::endl;
    file_descript = open(filename.c_str(), O_RDONLY);
    std::string res;
    file_size = fdGetFileSize(file_descript);
    printf("FILE SIZE  :\t%lu\n", file_size);
    if (file_descript < 0) {
    std::cout << "--------------------exit----------------------------\n";
    res="EMPTY FILE";
    return res;
    }
    file_buffer = (char*)mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    MD5((unsigned char *) file_buffer, file_size, result);
    munmap(file_buffer, file_size);
    char buf[32];
    int i;
    for(i=0; i<MD5_DIGEST_LENGTH;i++) {
        sprintf(buf, "%02x",result[i]);
        res.append(buf);
    }
    std::cout <<"MD5 VALUE  :\t"<<res<<std::endl;
    std::cout << "--------------------------------------------------------\n";
    END:
    return res;
};

/*std::string FilesVerification::generateSystemUniqueId() {
    uuid_t id;
    uuid_generate(id);
    char arrCh [64];
    uuid_unparse(id, arrCh);
    std::cout<< "generateSystemUniqueId =" << arrCh << std::endl;
    pUUIDStr = arrCh;
    return pUUIDStr;
}*/

FilesVerification::~FilesVerification() {

}
/*
std::string FilesVerification::getLicensefromDatabase(std::string queryStr) {
    MYSQL_RES *result;
    MYSQL_ROW row;
    MYSQL *connection, mysql;
    int state;
    std::string queryVal;
    const char *host = "localhost";
    const char *usr = "root";
    const char *pswd = "epicsystem";
    const char *database = "";

    mysql_init(&mysql);
    connection = mysql_real_connect(&mysql,host,usr,pswd,database,0,0,0);
    if (connection == NULL) {
        printf(mysql_error(&mysql));
        return "Error";
    }
    //std::string queryString = "SELECT LicenseNo FROM mytable WHERE uuid=" + "\"" + uuidStr + "\"";
    state = mysql_query(connection, queryStr.c_str());
    if (state !=0) {
        printf(mysql_error(connection));
           return "Error";
    }
    result = mysql_store_result(connection);
    printf("Rows:%d\n",mysql_num_rows(result));
    while(( row=mysql_fetch_row(result)) != NULL) {
        queryVal = row[0] ? row[0] : "" ;
         printf(" %s \n", (row[0] ? row[0] : "NULL"));
    }

    mysql_free_result(result);
    mysql_close(connection);
    return queryVal;
}
*/
std::string FilesVerification::getLicenseKeyfromServer(std::string data) {
    cout<< "getLicenseKeyfromServer IP\t= "<< urlString << endl;
    std::string urlStr = "http://";
    urlStr.append(urlString);
    urlStr.append("/apis/getLicenseDataByUUID");    //apis/getLicenseDataByUUID
    cout<< "getLicenseKeyfromServer\t\t= "<< urlStr << endl;
    char *res = webRequestResponse((char *)urlStr.c_str(), data.c_str());

    std::string strJson = responseString;
    Json::Value root;
    Json::Reader reader;
    // successful response from the server
    if(responseString != NULL) {
        bool parsingSuccessful = reader.parse(strJson.c_str(), root );     //parse process
        licenseKey = root.get("licenseKey", "NOVALUE" ).asString();
    }
    else {
        cout<<"No License found for this host !!!"<<endl;
    }
    std::cout << "\n--------------------------------------------------------\n";
    std::cout << "\t\tLICENSE KEY MATCH\n";
    std::cout << "--------------------------------------------------------\n";
    cout << "\nLicenseKey from Server\t\t= " << licenseKey << endl;
    return licenseKey;
}


std::string FilesVerification::getLicenseKeyfromFile(std::string file){
    std::ifstream Filee;
    Filee.open(file);
    std::string temp;
    while(!Filee.eof())
        Filee >> temp;
    cout << "LicenseKey from File\t\t= "<< temp << '\n';
    return temp;
}

std::string FilesVerification::getUUIDFromCommand(std::string cmd) {
    std::string data;
    FILE * stream;
    const int max_buffer = 256;
    char buffer[max_buffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
            pclose(stream);
    }
    char *compStr = NULL;
    char *rmStr = "UUID: ";
    compStr = strstr((char *)data.c_str(), rmStr);
    std::string queryString = "";
    if(compStr != NULL) {
        compStr += strlen(rmStr);
        return compStr;
    }
    else {
        return data;
    }
}

std::string FilesVerification::getQueryString(std::string commandStr, query qr) {

    std::string queryString = "";
    if(qr == LICENSE) {
        queryString = "SELECT LicenseNo FROM mytable WHERE uuid=";
        queryString.append("\"" );
        queryString.append(commandStr);
        queryString.append( "\"");
    }
    return queryString;
}
/** @function main()
 *  @purpose To check current time and hit api regulary with time duration
 */
int main(int argc, char **argv) {
    std::cout << "--------------------------------------------------------\n";
    std::cout << "\t\tENTERED URL & UUID\n";
    std::cout << "--------------------------------------------------------\n";
    std::string url = "";
    if(argc > 1) {
        url = argv[1];
        cout << "URL of Server\t\t\t= " << url <<endl;
    }
    else {
        cout << "Please Enter Server URL !!!" <<endl;
        exit(0);
    }
        FilesVerification objAuth((char *)url.c_str());
    // Get unique id for the host m/c
    std::string uuidStr = "";
    if( (uuidStr = objAuth.getUUIDFromCommand("sudo dmidecode -t system | grep \"UUID\"")) != "") {
        std::cout << "uuidStr\t\t\t\t= " << uuidStr << "\n";
    }
    else {
        std::cout << "NO License is generated for this host m/c Please contact to Admin !!!" <<std::endl;
    }
    do{
    std::cout << "--------------------------------------------------------\n";
    std::cout << "\t\tLETS GET SERVER RESPONSE\n";
    std::cout << "--------------------------------------------------------\n";
    // Get the license key for the host from the server
    std::string keyServer = "";
    keyServer = objAuth.getLicenseKeyfromServer(uuidStr);
    std::string keyFile = "";
    keyFile = objAuth.getLicenseKeyfromFile("license.lic");
    if(keyServer==keyFile) {
        matchFound = true;
        cout<<"License Key Match Result\t: TRUE !!!"<<endl;
        std::cout << "\n--------------------------------------------------------\n";
        std::cout << "\t\t\tTIME CHECK\n";
        std::cout << "--------------------------------------------------------\n";
        std::cout << "TIME CHECK H ="<< TIMECHECK_H <<std::endl;
        std::cout << "TIME CHECK M ="<< TIMECHECK_M <<std::endl;
        do{
            sleep(SYSTEMWAIT);
            std::time_t t = std::time(0);
            std::tm *now = std::localtime(&t);
            std::string timenow = ctime(&t);
            std::cout << "TIME CHECK timenow H =" << now->tm_hour<<std::endl;
            std::cout << "TIME CHECK timenow M =" << now->tm_min<<std::endl;
            //int check = timenow.find(TIMECHECK);
            //printf("\tTimeNow\t: %s",ctime(&t));
            //if(check != -1){
            if((now->tm_hour == TIMECHECK_H) && (now->tm_min == TIMECHECK_M)) {
                //keyServer = objAuth.getLicenseKeyfromServer(uuidStr);
                std::cout << "--------------------------------------------------------\n";
                printf("\t\tTIME CHECK FOUND\n");
                objAuth.parseFileFromJson();
                printf(" .---------------.\n");
                printf("|  HELLO LICENSE  |\n");
                printf(" '---------------'\n");
                std::cout << "-------------------------------------------------------\n\n";
            }
            if(matchFound != true) {
                cout<<"MD5 NOT MATCH  :   ABORT  |"<<endl;
                int x = system("sudo systemctl stop epic");
                std::cout<< "STOP EPIC IF FORCEFULLY RUN ="<< x <<std::endl;
            }
            //else
            //    printf("\n");
        }while (1);

        }
    else {
                matchFound = false;
             cout<<"License Key Match Result\t: FALSE !!!"<<endl;
        cout<<"From Server : "<<keyServer<<" || From File : "<<keyFile<<endl;
        int x = system("sudo systemctl stop epic");
        sleep(SYSTEMWAIT);
        //exit(0);
    }}while(1);
    cout << "END of the main function " <<endl;

    return 0;
};
