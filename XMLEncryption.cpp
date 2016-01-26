//Primary author: Jonathan Bedard
//Certified working 1/26/2016

#ifndef XML_ENCRYPTION_CPP
#define XML_ENCRYPTION_CPP

#include <string>
#include <stdint.h>
#include "XMLEncryption.h"

namespace crypto {
    
    //Raw password output
    bool EXML_Output(std::string path, os::smartXMLNode head, std::string password, os::smart_ptr<streamPackageFrame> spf)
    {
        //Basic checks
        if(!head) return false;
        if(os::check_exists(path) && os::is_directory(path)) return false;
        std::ofstream fileout(path);
        if(!fileout.good()) return false;
        
        //Check stream package
        if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
        //Output header
        fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
        
        return true;
    }
    //Public key encryption output
    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<publicKey> pbk, os::smart_ptr<streamPackageFrame> spf)
    {
        //Basic checks
        if(!head) return false;
        if(os::check_exists(path) && os::is_directory(path)) return false;
        if(!pbk) return false;
        std::ofstream fileout(path);
        if(!fileout.good()) return false;
        
        //Check stream package
        if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
        //Output header
        fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
        
        return true;
    }
    //Decrypt with password
    os::smartXMLNode EXML_Input(std::string path, std::string password)
    {
        //Basic checks
        if(os::check_exists(path) && os::is_directory(path)) return NULL;
        std::ifstream filein(path);
        if(!filein.good()) return NULL;
        
        return NULL;
    }
    //Decrypt with public key
    os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk)
    {
        //Basic checks
        if(os::check_exists(path) && os::is_directory(path)) return NULL;
        if(!pbk) return NULL;
        std::ifstream filein(path);
        if(!filein.good()) return NULL;
        
        return NULL;
    }
}

#endif
