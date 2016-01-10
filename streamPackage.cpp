//Primary author: Jonathan Bedard
//Certified working 1/10/2016

#ifndef STREAM_PACKAGE_CPP
#define STREAM_PACKAGE_CPP

#include <string>
#include <stdint.h>
#include "streamEXML.h"

namespace crypto {
/*------------------------------------------------------------
     Stream Package
 ------------------------------------------------------------*/
    
    os::smart_ptr<streamPackageTypeBank> _singleton;
    //Stream package constructor
    streamPackageTypeBank::streamPackageTypeBank()
    {
        //RC-Four stream, RC4 hash
        pushPackage(os::smart_ptr<streamPackageFrame>(new streamPackage<RCFour,rc4Hash>(),os::shared_type));
    }
    //Singleton constructor
    os::smart_ptr<streamPackageTypeBank> streamPackageTypeBank::singleton()
    {
        if(!_singleton) _singleton=os::smart_ptr<streamPackageTypeBank>(new streamPackageTypeBank(),os::shared_type);
        return _singleton;
    }
    
    //Sets the default package value
    void streamPackageTypeBank::setDefaultPackage(os::smart_ptr<streamPackageFrame> package)
    {
        pushPackage(package);
    }
    //Add a package to the package list
    void streamPackageTypeBank::pushPackage(os::smart_ptr<streamPackageFrame> package)
    {
        if(!package) return;
        
        
    }
    //Given stream descriptions, find package
    os::smart_ptr<streamPackageFrame> streamPackageTypeBank::findStream(uint16_t streamID,uint16_t hashID)
    {
        if(streamID>packageVector.size()) return NULL;
        if(!packageVector[streamID]) return NULL;
        
        if(hashID>packageVector[streamID]->size()) return NULL;
        return (*packageVector[streamID])[hashID];
    }
}

#endif
