/** @file LicenseViewPath.h
 *  @purpose Verify the change in files, license verification
 *  and authentication of the module
 *  @author Rsystems Ltd.
 */

#ifndef __LICENSEVIEWPATH_H_INCLUDED__
#define __LICENSEVIEWPATH_H_INCLUDED__

#include <map>
#include <string>
#include <iostream>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <iomanip>
#include <uuid/uuid.h> //sudo apt-get install uuid-dev
#include <unistd.h>
#include <jsoncpp/json/json.h> //sudo apt-get install libjsoncpp-dev
#include <curl/curl.h> // sudo apt-get install libcurl-dev or udo apt-get install libcurl4-openssl-dev
                       // or sudo apt-get install libcurl4-gnutls-dev
#include <sys/time.h>
#include <stdio.h>
//#include <mysql.h>
#include <regex>

#include <fstream>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

/** @global Function webRequestResponse
 *  @purpose Send request to the server for data verification and get response of valid data
 *  @param char pointer to the url
 *  @return char pointer to the response
 */
char *webRequestResponse(char *url, const char *httpData);
int valid_digit(char *ip_str);
int is_valid_ip(char *ip_str);

enum keyMatch {IDLE=0, MATCH, NOTMATCH};
enum query {LICENSE=0, UUID};

static bool matchFound = 0;
//void function_pt(void *ptr, size_t size, size_t nmemb);

/** @class FilesVerification
 *  @Purpose check the file authentication
 */
class FilesVerification {
public:
    // returned response from the server
    static char *responseString;
    std::string pUUIDStr;
    // parameterised constructor
    FilesVerification(char *url);
    ~FilesVerification();

    std::string getLicensefromDatabase(std::string uuidStr);
    std::string getLicenseKeyfromServer(std::string httpData);
    std::string getLicenseKeyfromFile(std::string file);
    std::string getQueryString(std::string, query qr);

    //std::string generateSystemUniqueId();

    std::string getUUIDFromCommand(std::string cmd);

    /** @method getFileListFromServer
     *  @purpose request the file list from the server for authenticate
     *  @param void
     *  @return void
     */
    void getFileListFromServer();

    /** @method parseFileFromJson
     *  @purpose parse the response of the server
     *  @param void
     *  @return bool in-case file is invalid
     */
    void parseFileFromJson();
    std::string printMD5(unsigned char* md, long size = MD5_DIGEST_LENGTH);

    static void function_pt(void *ptr, unsigned int size, unsigned int nmemb);

private:
    // url of the server
    std::string urlString;
    std::string licenseKey;
    std::string versionApp;
    std::string uniqueHWId;
    bool validLicense;
    // map contain file name vs md5 checksum
    std::map<std::string, std::string> mapFileList;

    /** @method md5_for_file
     *  @purpose generate md5 checksum value for the verification from the server
     *  @param char * filename for which md5 checksum value generate
     *  @return unsigned char * md5 checksum value
     */
    std::string md5_for_file(std::string filename);

    /** @method fdGetFileSize
     *  @purpose get file size from the file descriptor
     *  @param int file descriptor
     *  @return long size of file
     */
    long fdGetFileSize(int fd);

};

/** @class LicenseVerification
 *  @Purpose check the license authentication
 */
class LicenseVerification {

};

/** @class ServiceMonitoring
 *  @Purpose check the service status and in-case failure of any service restart
 *  the backup
 */
class ServiceMonitoring {

};


#endif //__LICENSEVIEWPATH_H_INCLUDED__
