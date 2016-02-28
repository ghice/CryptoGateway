/**
 * @file   keyBank.cpp
 * @author Jonathan Bedard
 * @date   2/21/2016
 * @brief  Implimentation for the AVL tree based key bank
 * @bug No known bugs.
 *
 * This file contians the implimentation for the
 * crypto::avlKeyBank and supporting classes.
 * Consult keyBank.h for details.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_CPP
#define GATEWAY_CPP

#include "keyBank.h"
#include "cryptoError.h"
#include "XMLEncryption.h"
#include <sstream>

namespace crypto {
    
/*-----------------------------------
     Node Group
  -----------------------------------*/
    
    //Constructs a nodeName with an XML tree
	nodeGroup::nodeGroup(keyBank* master,os::smartXMLNode fileNode)
	{
		if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
		_master=master;
		sortingLock.lock();
		try
		{
			if(fileNode->getID()!="nodeGroup") throw errorPointer(new fileFormatError(),os::shared_type);
			
			//Names
			auto list1=fileNode->findElement("names");
			if(list1->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
			os::smartXMLNode secondLevel=list1->getFirst()->getData();
			auto list2=secondLevel->findElement("name");
			if(list2->size()<=0) throw errorPointer(new fileFormatError(),os::shared_type);

			//Insert name block
			for(auto block=list2->getFirst();block;block=block->getNext())
			{
				//Group
				auto parseList=block->getData()->findElement("group");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string gn=parseList->getFirst()->getData()->getData();

				//Name
				parseList=block->getData()->findElement("name");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string nm=parseList->getFirst()->getData()->getData();

				//Timestamp
				parseList=block->getData()->findElement("timestamp");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				uint64_t times=0;
				std::stringstream(parseList->getFirst()->getData()->getData())>>times;
				if(times==0) throw errorPointer(new fileFormatError(),os::shared_type);

				//Construct
				os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,gn,nm,times),os::shared_type);
				if(nameList.insert(nameInsert))
					_master->pushNewNode(nameInsert);
			}

			//Keys
			list1=fileNode->findElement("keys");
			if(list1->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
			secondLevel=list1->getFirst()->getData();
			list2=secondLevel->findElement("key");
			if(list2->size()<=0) throw errorPointer(new fileFormatError(),os::shared_type);

			//Insert key block
			for(auto block=list2->getFirst();block;block=block->getNext())
			{
				//Key size
				auto parseList=block->getData()->findElement("keySize");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				uint16_t ks=std::stoi(parseList->getFirst()->getData()->getData())/32;

				//Algo ID
				parseList=block->getData()->findElement("algo");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string ali=parseList->getFirst()->getData()->getData();

				//Timestamp
				parseList=block->getData()->findElement("timestamp");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				uint64_t times=0;
				std::stringstream(parseList->getFirst()->getData()->getData())>>times;
				if(times==0) throw errorPointer(new fileFormatError(),os::shared_type);

				//Key
				parseList=block->getData()->findElement("key");
				if(parseList->size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				auto hld=parseList->getFirst()->getData();
				if(hld->getDataList().size()!=ks) throw errorPointer(new fileFormatError(),os::shared_type);
				os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(ali);
				if(!pkfrm) throw errorPointer(new fileFormatError(),os::shared_type);
				pkfrm->getCopy();
				if(!pkfrm) throw errorPointer(new fileFormatError(),os::shared_type);
				pkfrm->setKeySize(ks);
				uint32_t* keyArr=new uint32_t[ks];
				for(unsigned int arrcnt=0;arrcnt<ks;arrcnt++)
					std::stringstream(hld->getDataList()[arrcnt])>>keyArr[arrcnt];
				os::smart_ptr<number> key=pkfrm->convert(keyArr,ks);
				delete [] keyArr;

				//Construct
				os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,pkfrm->algorithm(),ks,times),os::shared_type);
				if(keyList.insert(keyInsert))
					_master->pushNewNode(keyInsert);
			}

			//Sort inserted elements
			sortKeys();
			sortNames();
		}
		catch(errorPointer e)
		{
			sortingLock.unlock();
			throw e;
		}
		catch(...)
		{
			sortingLock.unlock();
			throw errorPointer(new unknownErrorType(),os::shared_type);
		}
		sortingLock.unlock();
	}
	//Node group constructor
    nodeGroup::nodeGroup(keyBank* master,std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
		_master=master;
		try
		{
			sortingLock.lock();
			os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name),os::shared_type);
			if(nameList.insert(nameInsert))
				_master->pushNewNode(nameInsert);
			else throw errorPointer(new insertionFailed(),os::shared_type);
			os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize),os::shared_type);
			if(keyList.insert(keyInsert))
				_master->pushNewNode(keyInsert);
			else throw errorPointer(new insertionFailed(),os::shared_type);
			sortKeys();
			sortNames();
		}
		catch(errorPointer e)
		{
			sortingLock.unlock();
			throw e;
		}
		catch(...)
		{
			sortingLock.unlock();
			throw errorPointer(new unknownErrorType(),os::shared_type);
		}
		sortingLock.unlock();
    }
	//Returns the name of a node group
	void nodeGroup::getName(std::string& groupName,std::string& name)
	{
		sortingLock.lock();
		
		//No array case
		if(!sortedNames || !sortedNames[0])
		{
            os::smart_ptr<nodeNameReference> ref=sortedNames[0];
			groupName="";
			name="";
		}
		else
		{
			groupName=sortedNames[0]->groupName();
			name=sortedNames[0]->name();
		}
		sortingLock.unlock();
	}
	//Returns the name of a node group
	std::string nodeGroup::name()
	{
		std::string gn,nm;
		getName(gn,nm);
		return gn+":"+nm;
	}
	
	//Merges two node groups
	void nodeGroup::merge(nodeGroup& source)
	{
		sortingLock.lock();
		if(source._master!=_master) throw errorPointer(new masterMismatch(),os::shared_type);
		auto trc1=source.nameList.getFirst();
		while(trc1)
		{
			trc1->getData()->_master=this;
			nameList.insert(trc1->getData());
			trc1=trc1->getNext();
		}
		auto trc2=source.keyList.getFirst();
		while(trc2)
		{
			trc2->getData()->_master=this;
			keyList.insert(trc2->getData());
			trc2=trc2->getNext();
		}
		sortKeys();
		sortNames();
		sortingLock.unlock();
	}
	//Adds an alias to the current node
	void nodeGroup::addAlias(std::string groupName,std::string name,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name,timestamp),os::shared_type);
        if(nameList.insert(nameInsert))
			_master->pushNewNode(nameInsert);
		sortNames();
		sortingLock.unlock();
	}
	//Adds a key to the current node
	void nodeGroup::addKey(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize,timestamp),os::shared_type);
        if(keyList.insert(keyInsert))
			_master->pushNewNode(keyInsert);
		sortKeys();
		sortingLock.unlock();
	}

	//Compare keys by timestamp
	int compareKeysByTimestamp(os::smart_ptr<nodeKeyReference> ref1, os::smart_ptr<nodeKeyReference> ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return -1;
		if(ref1->timestamp()<ref2->timestamp())
			return 1;
		return 0;
	}
	//Compare names by timestamp
	int compareNamesByTimestamp(os::smart_ptr<nodeNameReference> ref1, os::smart_ptr<nodeNameReference> ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return -1;
		if(ref1->timestamp()<ref2->timestamp())
			return 1;
		return 0;
	}
	//Preforms quicksort on keys by timestamp
	void nodeGroup::sortKeys()
	{
		sortedKeys=os::smart_ptr<os::smart_ptr<nodeKeyReference> >(new os::smart_ptr<nodeKeyReference>[keyList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=keyList.getFirst();i;i=i->getNext())
		{
			sortedKeys[cnt]=i->getData();
			cnt++;
		}
		os::pointerQuicksort(sortedKeys,cnt,&compareKeysByTimestamp);
	}
	//Preforms quicksort on names by timestamp
	void nodeGroup::sortNames()
	{
		sortedNames=os::smart_ptr<os::smart_ptr<nodeNameReference> >(new os::smart_ptr<nodeNameReference>[nameList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=nameList.getFirst();i;i=i->getNext())
		{
			sortedNames[cnt]=i->getData();
			cnt++;
		}
		os::pointerQuicksort(sortedNames,cnt,&compareNamesByTimestamp);
	}
    
	//Return list of name nodes by timestamp
	os::smart_ptr<os::smart_ptr<nodeNameReference> > nodeGroup::namesByTimestamp(unsigned int& size)
	{
		sortingLock.lock();
		size=nameList.size();
		os::smart_ptr<os::smart_ptr<nodeNameReference> > ret=sortedNames;
		sortingLock.unlock();
		return ret;
	}
	//Return list of key nodes by timestamp
	os::smart_ptr<os::smart_ptr<nodeKeyReference> > nodeGroup::keysByTimestamp(unsigned int& size)
	{
		sortingLock.lock();
		size=keyList.size();
		os::smart_ptr<os::smart_ptr<nodeKeyReference> > ret=sortedKeys;
		sortingLock.unlock();
		return ret;
	}

    //Builds XML tree
    os::smartXMLNode nodeGroup::buildXML()
    {
        os::smartXMLNode ret(new os::XML_Node("nodeGroup"),os::shared_type);
        
        //Name list
        os::smartXMLNode tlevel(new os::XML_Node("names"),os::shared_type);
        for(auto i=nameList.getFirst();i;i=i->getNext())
        {
            os::smartXMLNode nlev(new os::XML_Node("name"),os::shared_type);
            
            //Group
            os::smartXMLNode temp(new os::XML_Node("group"),os::shared_type);
            temp->setData(i->getData()->groupName());
            nlev->addElement(temp);
            
            //Name
            temp=os::smartXMLNode(new os::XML_Node("name"),os::shared_type);
            temp->setData(i->getData()->name());
            nlev->addElement(temp);
            
            //Timestamp
            temp=os::smartXMLNode(new os::XML_Node("timestamp"),os::shared_type);
            temp->setData(std::to_string(i->getData()->timestamp()));
            nlev->addElement(temp);
            
            tlevel->addElement(nlev);
        }
        ret->addElement(tlevel);
        
        //Key list
        tlevel=os::smartXMLNode(new os::XML_Node("keys"),os::shared_type);
        for(auto i=keyList.getFirst();i;i=i->getNext())
        {
            os::smartXMLNode klev(new os::XML_Node("key"),os::shared_type);
            tlevel->addElement(klev);
            
            //Key
            os::smartXMLNode temp(new os::XML_Node("key"),os::shared_type);
            for(unsigned t=0;t<i->getData()->keySize();t++)
                temp->getDataList().push_back(std::to_string((*i->getData()->key())[t]));
            klev->addElement(temp);
            
            //Key size
            temp=os::smartXMLNode(new os::XML_Node("keySize"),os::shared_type);
            temp->setData(std::to_string(i->getData()->keySize()*32));
            klev->addElement(temp);
            
            //Algorithm
            temp=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(i->getData()->algoID());
			if(!pkfrm) pkfrm=publicKeyTypeBank::singleton()->defaultPackage();
			temp->setData(pkfrm->algorithmName());
            klev->addElement(temp);
            
            //Timestamp
            temp=os::smartXMLNode(new os::XML_Node("timestamp"),os::shared_type);
            temp->setData(std::to_string(i->getData()->timestamp()));
            klev->addElement(temp);
        }
        ret->addElement(tlevel);
        
        return ret;
    }
    
/*-----------------------------------
    Node Name Reference
  -----------------------------------*/
    
    //Name reference constructor
    nodeNameReference::nodeNameReference(nodeGroup* master,std::string groupName,std::string name,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        _master=master;
        _groupName=groupName;
        _name=name;
        _timestamp=timestamp;
    }
    //Designed for searching
	nodeNameReference::nodeNameReference(std::string groupName,std::string name)
	{
		_master=NULL;
        _groupName=groupName;
        _name=name;
        _timestamp=os::getTimestamp();
	}
	//Use group name and name to compare
    int nodeNameReference::compare(const nodeNameReference& comp)const
    {
        int compV=_groupName.compare(comp._groupName);
        if(compV>0) return 1;
        else if(compV<0) return -1;
        
        compV=_name.compare(comp._name);
        if(compV>0) return 1;
        else if(compV<0) return -1;
        
        return 0;
    }

/*-----------------------------------
     Node Key Reference
-----------------------------------*/
    
    //Name reference constructor
    nodeKeyReference::nodeKeyReference(nodeGroup* master,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);
        
        _master=master;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=timestamp;
    }
    //Designed for seraching
	nodeKeyReference::nodeKeyReference(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
	{
		if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);

		_master=NULL;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=os::getTimestamp();
	}
	//Use group name and name to compare
    int nodeKeyReference::compare(const nodeKeyReference& comp)const
    {
        int dif = _algoID-comp._algoID;
        if(dif>0) return 1;
        else if(dif<0) return -1;
        dif = _keySize-comp._keySize;
        if(dif>0) return 1;
        else if(dif<0) return -1;
        return _key->compare(comp._key.get());
    }
    
/*-----------------------------------
	Key Bank
-----------------------------------*/

	//Key bank constructor
	keyBank::keyBank(std::string savePath,const unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> strmPck)
	{
		_savePath=savePath;

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
		if(key==NULL || keyLen==0)
		{
			_symKey=NULL;
			_keyLen=0;
		}
		else
		{
			_symKey=new unsigned char[keyLen];
			memcpy(_symKey,key,keyLen);
			_keyLen=keyLen;
		}

		//Stream package
		_streamPackage=strmPck;
		if(_streamPackage)
			_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
		markChanged();
	}
	//Set password
	void keyBank::setPassword(const unsigned char* key,unsigned int keyLen)
	{
		//Set key
		if(_symKey!=NULL)
			delete [] _symKey;

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
		if(key==NULL || keyLen==0)
		{
			_symKey=NULL;
			_keyLen=0;
		}
		else
		{
			_symKey=new unsigned char[keyLen];
			memcpy(_symKey,key,keyLen);
			_keyLen=keyLen;
		}

		markChanged();
	}
	//Set stream package
	void keyBank::setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack)
	{
		_streamPackage=strmPack;
		if(_streamPackage)
			_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
		markChanged();
	}

/*-----------------------------------
     AVL Key Bank
-----------------------------------*/
    
    //AVL bank constructor
    avlKeyBank::avlKeyBank(std::string savePath,const unsigned char* key,unsigned int keyLen,os::smart_ptr<streamPackageFrame> strmPck):
        keyBank(savePath,key,keyLen,strmPck)
    {
        load();
    }
    //Load file
    void avlKeyBank::load()
    {
		if(savePath()=="") return;
		try
		{
			os::smartXMLNode headNode;

			//Have a symetric key
			if(_symKey!=NULL&&_keyLen>0) headNode=EXML_Input(savePath(),_symKey,_keyLen);
			//No encryption
			else headNode=os::XML_Input(savePath());

			if(!headNode)
				throw errorPointer(new fileOpenError(),os::shared_type);
			if(headNode->getID()!="keyBank")
				throw errorPointer(new fileFormatError(),os::shared_type);

			//Iterate through children
			auto it=headNode->getChildren()->getFirst();
			while(it)
			{
				os::smart_ptr<nodeGroup> nd=fileLoadHelper(it->getData());
				nodeBank.insert(nd);
				it=it->getNext();
			}
		}
		catch (errorPointer e) {logError(e);}
		catch (...) {logError(errorPointer(new unknownErrorType(),os::shared_type));}
    }
    //Save file
    void avlKeyBank::save()
    {
		if(savePath()=="")
		{
			errorSaving("No saving path");
			return;
		}
		try
		{
			os::smartXMLNode headNode(new os::XML_Node("keyBank"),os::shared_type);
			for(auto i=nodeBank.getFirst();i;i=i->getNext())
				headNode->addElement(i->getData()->buildXML());

			//Have a symetric key
			if(_symKey!=NULL&&_keyLen>0)
			{
				if(!EXML_Output(savePath(),headNode,_symKey,_keyLen,_streamPackage))
					throw errorPointer(new fileOpenError(),os::shared_type);
			}
			//No encryption
			else
			{
				if(!os::XML_Output(savePath(), headNode))
					throw errorPointer(new fileOpenError(),os::shared_type);
			}
		}
		catch (errorPointer e)
		{
			logError(e);
			errorSaving(e->errorTitle());
			return;
		}
		catch (...) 
		{
			logError(errorPointer(new unknownErrorType(),os::shared_type));
			errorSaving("Unknown error");
			return;
		}
		finishedSaving();
    }
    
    //Push node (name)
    void avlKeyBank::pushNewNode(os::smart_ptr<nodeNameReference> name)
	{
		nameTree.insert(name);
		markChanged();
	}
    //Push node (key)
    void avlKeyBank::pushNewNode(os::smart_ptr<nodeKeyReference> key)
	{
		keyTree.insert(key);
		markChanged();
	}
    
    //Add authenticated node
    os::smart_ptr<nodeGroup> avlKeyBank::addPair(std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
    {
        os::smart_ptr<nodeGroup> foundName=keyBank::find(groupName,name);
        os::smart_ptr<nodeGroup> foundKey=keyBank::find(key,algoID,keySize);
        
        os::smart_ptr<nodeGroup> ret;
        //Neither case
        if(!foundName && !foundKey)
        {
            ret=os::smart_ptr<nodeGroup>(new nodeGroup(this,groupName,name,key,algoID,keySize),os::shared_type);
            nodeBank.insert(ret);
        }
        //Only found the key
        else if(!foundName && foundKey)
        {
            foundKey->addAlias(groupName,name);
            ret=foundKey;
        }
        //Only found the name
        else if(foundName && !foundKey)
        {
            foundName->addKey(key,algoID,keySize);
            ret=foundName;
        }
        //Both name and key were found, but are seperate
        else if(foundName!=foundKey)
        {
            nodeBank.findDelete(foundKey);
            foundName->merge(*foundKey);
            ret=foundName;
        }
        //Name and key are the same
        else ret=foundName;
		markChanged();
        return ret;
    }
    //Find node (name)
    os::smart_ptr<nodeGroup> avlKeyBank::find(os::smart_ptr<nodeNameReference> name)
    {
        auto temp=nameTree.find(name);
        if(!temp) return NULL;
        name=temp->getData();
        nodeGroup* ref=name->master();
        if(!ref) NULL;
        
        auto trc = nodeBank.find(ref);
        if(!trc) return NULL;
        return trc->getData();
    }
    //Fine node (key)
    os::smart_ptr<nodeGroup> avlKeyBank::find(os::smart_ptr<nodeKeyReference> key)
    {
        auto temp=keyTree.find(key);
        if(!temp) return NULL;
        key=temp->getData();
        nodeGroup* ref=key->master();
        if(!ref) NULL;
        
        auto trc = nodeBank.find(ref);
        if(!trc) return NULL;
        return trc->getData();
    }
}

#endif

///@endcond
