/**
 * @file	XMLEncryption.cpp
 * @author	Jonathan Bedard
 * @date   	8/26/2016
 * @brief	Implements encrypted XML functions
 * @bug	None
 *
 * Implements functions to save and load XML trees
 * in files locked with both a password and with
 * public keys.
 **/

 ///@cond INTERNAL
 
#ifndef XML_ENCRYPTION_CPP
#define XML_ENCRYPTION_CPP

#include <string>
#include <stdint.h>
#include "XMLEncryption.h"
#include "cryptoError.h"
#include "keyBank.h"

namespace crypto {

    //Generate arguments list
	static std::vector<std::string> generateArgumentList(os::smartXMLNode head)
	{
		std::vector<std::string> ret;
		unsigned int trc1=0;
		unsigned int trc2=0;

		ret.push_back(head->getID());
		std::vector<std::string> temp;
		for(auto it=head->getChildren()->first();it;++it)
		{
			temp=generateArgumentList(&it);
			for(trc1=0;trc1<temp.size();trc1++)
			{
				bool found=false;
				for(trc2=0;trc2<ret.size()&&!found;trc2++)
				{
					if(ret[trc2]==temp[trc1])
						found=true;
				}
				if(!found) ret.push_back(temp[trc1]);
			}
		}

		return ret;
	}
    //Given an XML node, a stream encryptor, an argument vector and a file, print it
	static void recursiveXMLPrinting(os::smartXMLNode head,os::smart_ptr<streamCipher> strm,std::vector<std::string> args,std::ofstream& ofs)
	{
		//Throw -1 if error
		if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
		if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);

		//Contains: index, number of children, amount of data
		unsigned char headerData [6];
		memset(headerData,0,6);
		uint16_t data=(uint16_t)args.size()+1;

		//Index
		for(unsigned int i=0;i<args.size()&&data>args.size();++i)
		{
			if(args[i]==head->getID())
				data=i;
		}
		data=os::to_comp_mode(data);
		memcpy(headerData,&data,2);

		//Number of children
		if(head->getChildren()->size()>0)
		{
			data=head->getChildren()->size();
			data=os::to_comp_mode(data);
			memcpy(headerData+2,&data,2);
		}
		//Amount of data
		else
		{
			data=0;
			if(head->getData()!="")
				data=1;
			else if(head->getDataList().size()>0)
				data=(uint16_t)head->getDataList().size();
			data=os::to_comp_mode(data);
			memcpy(headerData+4,&data,2);
		}

		for(unsigned int i=0;i<6;++i)
			headerData[i]=headerData[i]^strm->getNext();
		ofs.write((char*)headerData,6);

		//Output children
		if(head->getChildren()->size()>0)
		{
			for(auto trc=head->getChildren()->first();trc;++trc)
				recursiveXMLPrinting(&trc,strm,args,ofs);
		}
		//Output data
		else
		{
			os::smart_ptr<unsigned char> dataptr;
			if(head->getData()!="")
			{
				dataptr=os::smart_ptr<unsigned char>(new unsigned char[head->getData().size()+2],os::shared_type_array);
				data=(uint16_t)head->getData().size();
				data=os::to_comp_mode(data);
				memcpy(dataptr.get(),&data,2);
				memcpy(dataptr.get()+2,head->getData().c_str(),head->getData().size());
				for(unsigned int en=0;en<head->getData().size()+2;en++)
					dataptr[en]=dataptr[en]^strm->getNext();
				ofs.write((char*)dataptr.get(),head->getData().size()+2);
			}
			else
			{
				for(unsigned int i=0;i<head->getDataList().size();++i)
				{
					dataptr=os::smart_ptr<unsigned char>(new unsigned char[head->getDataList()[i].size()+2],os::shared_type_array);
					data=(uint16_t)head->getDataList()[i].size();
					data=os::to_comp_mode(data);
					memcpy(dataptr.get(),&data,2);
					memcpy(dataptr.get()+2,head->getDataList()[i].c_str(),head->getDataList()[i].size());
					for(unsigned int en=0;en<head->getDataList()[i].size()+2;en++)
						dataptr[en]=dataptr[en]^strm->getNext();
					ofs.write((char*)dataptr.get(),head->getDataList()[i].size()+2);
				}
			}
		}
	}
	//Build an XML tree from an EXML file
	static os::smartXMLNode recursiveXMLBuilding(os::smart_ptr<streamCipher> strm,std::vector<std::string> args,std::ifstream& ifs)
	{
		if(!strm)
			throw errorPointer(new NULLDataError(),os::shared_type);
		if(!ifs.good())
			throw errorPointer(new actionOnFileError(),os::shared_type);
		unsigned char headerData [6];

		ifs.read((char*)headerData,6);
		//Decrypt
		for(unsigned int i=0;i<6;++i)
			headerData[i]=headerData[i]^strm->getNext();
		uint16_t data;

		//Index
		memcpy(&data,headerData,2);
		data=os::from_comp_mode(data);
		if(data>=args.size())
			throw errorPointer(new customError("ID Index out-of-bound","Expected index less than "+std::to_string((long long unsigned int)args.size())+" but found index "+std::to_string((long long unsigned int)data)),os::shared_type);
		os::smartXMLNode ret(new os::XML_Node(args[data]),os::shared_type);

		//Number of children
		memcpy(&data,headerData+2,2);
		data=os::from_comp_mode(data);
		if(data>0)
		{
			for(unsigned int i=0;i<data;++i)
			{
				if(!ifs.good())
					throw errorPointer(new actionOnFileError(),os::shared_type);
				ret->addElement(recursiveXMLBuilding(strm,args,ifs));
			}
			return ret;
		}

		//Amount of data
		memcpy(&data,headerData+4,2);
		data=os::from_comp_mode(data);
		std::vector<std::string> pData;
		for(unsigned int i=0;i<data;++i)
		{
			if(!ifs.good())
				throw errorPointer(new actionOnFileError(),os::shared_type);
			//Find string length
			uint16_t strLen;

			ifs.read((char*)headerData,2);
			headerData[0]=headerData[0]^strm->getNext();
			headerData[1]=headerData[1]^strm->getNext();
			memcpy(&strLen,headerData,2);
			strLen=os::from_comp_mode(strLen);
			char* str=new char[strLen+1];
			ifs.read(str,strLen);
			for(unsigned s=0;s<strLen;s++)
				str[s]=str[s]^strm->getNext();
			str[strLen]='\0';
			pData.push_back(std::string(str));
			delete [] str;
		}
		if(pData.size()==1) ret->setData(pData[0]);
		else
		{
			for(unsigned int i=0;i<pData.size();++i)
				ret->getDataList().push_back(pData[i]);
		}

		return ret;
	}

	//Raw password output
    bool EXML_Output(std::string path, os::smartXMLNode head, std::string password, os::smart_ptr<streamPackageFrame> spf)
	{
		return EXML_Output(path,head,(unsigned char*) password.c_str(),password.length(),spf);
	}
    bool EXML_Output(std::string path, os::smartXMLNode head, unsigned char* symKey,size_t passwordLength, os::smart_ptr<streamPackageFrame> spf)
	{
		try
		{
			//Basic checks
			if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);;
			std::ofstream fileout(path,std::ios::binary);
			if(!fileout.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Password size check
			if(passwordLength>size::STREAM_SEED_MAX)
				throw errorPointer(new passwordLargeError(),os::shared_type);
			if(passwordLength<=0)
				throw errorPointer(new passwordSmallError(),os::shared_type);
        
			//Check stream package
			if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
			//Output header
			fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			os::smartXMLNode encryHead(new os::XML_Node("header"),os::shared_type);
        
			//Public key type
			os::smartXMLNode trc1(new os::XML_Node("public_key"),os::shared_type);
			os::smartXMLNode trc2;
			trc1->setData("none");
			encryHead->addElement(trc1);
        
			//Stream
			trc1=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->streamAlgorithmName());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Hash
			trc1=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->hashAlgorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)spf->hashSize()*8));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Key
			trc1=os::smartXMLNode(new os::XML_Node("key"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			hash hsh=spf->hashData(symKey,passwordLength);
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Data list
			std::vector<std::string> argList=generateArgumentList(head);
			trc1=os::smartXMLNode(new os::XML_Node("argList"),os::shared_type);
			for(unsigned int i=0;i<argList.size();++i)
				trc1->getDataList().push_back(argList[i]);
			encryHead->addElement(trc1);

			os::xml::writeNode(fileout,encryHead,0);

			os::smart_ptr<streamCipher> strm=spf->buildStream(symKey,passwordLength);
			if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			fileout<<'>';
			recursiveXMLPrinting(head,strm,argList,fileout);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string((long long int)e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return true;
    }
    //Public key encryption output
    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<publicKey> pbk, unsigned int lockType, os::smart_ptr<streamPackageFrame> spf)
    {
		//Encrypt with public key
		if(lockType==file::PRIVATE_UNLOCK)
			return EXML_Output(path,head,pbk->getN(),pbk->algorithm(),pbk->size());

		//Other types of encryption
		pbk->readLock();
		try
		{
			//Basic checks
			if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			if(!pbk) throw errorPointer(new NULLDataError(),os::shared_type);
			std::ofstream fileout(path,std::ios::binary);
			if(!fileout.good()) throw errorPointer(new fileOpenError(),os::shared_type);
        
			//Check stream package
			if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
			//Output header
			fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			os::smartXMLNode encryHead(new os::XML_Node("header"),os::shared_type);
        
			//Public key type
			os::smartXMLNode trc1(new os::XML_Node("public_key"),os::shared_type);
			os::smartXMLNode trc2(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(pbk->algorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)pbk->size()*32));
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("type"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)lockType));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Stream
			trc1=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->streamAlgorithmName());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Hash
			trc1=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->hashAlgorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)spf->hashSize()*8));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Generate key, and hash
			srand((unsigned)time(NULL));
			unsigned int kySize=pbk->size()*4;
			if(lockType==file::DOUBLE_LOCK)
				kySize=2*kySize;
			os::smart_ptr<unsigned char> randkey;
			randkey=os::smart_ptr<unsigned char>(new unsigned char[kySize],os::shared_type_array);
			memset(randkey.get(),0,kySize);
			for(uint16_t i=0;i<(pbk->size()-1)*4;++i)
				randkey[i]=rand();
			if(lockType==file::DOUBLE_LOCK)
			{
				for(uint16_t i=0;i<(pbk->size()-1)*4;++i)
					randkey[i+pbk->size()*4]=rand();
			}
			os::smart_ptr<number> num1=pbk->copyConvert(randkey.get(),pbk->size()*4);
			os::smart_ptr<number> num2;
			num1->reduce();
			if(lockType==file::DOUBLE_LOCK)
			{
				num2=pbk->copyConvert(randkey.get()+pbk->size()*4,pbk->size()*4);
				num2->reduce();
			}
			size_t keylen;
			os::smart_ptr<unsigned char> raw_key;
			if(lockType==file::DOUBLE_LOCK)
			{
				os::smart_ptr<unsigned char> tarr=num1->getCompCharData(keylen);
				raw_key=os::smart_ptr<unsigned char>(new unsigned char[keylen*2],os::shared_type);
				memcpy(raw_key.get(),tarr.get(),keylen);
				tarr=num2->getCompCharData(keylen);
				memcpy(raw_key.get()+keylen,tarr.get(),keylen);
				keylen=keylen*2;
			}
			else raw_key=num1->getCompCharData(keylen);
			if(!raw_key) throw errorPointer(new hashGenerationError(),os::shared_type);
			hash hsh=spf->hashData(raw_key.get(),keylen);
			if(lockType==file::DOUBLE_LOCK)
			{
				num1=pbk->decode(num1);
				num2=pbk->encode(num2);
				num1->reduce();
				num2->reduce();
			}
			else
			{
				num1=pbk->decode(num1);
				num1->reduce();
			}

			//Key
			trc1=os::smartXMLNode(new os::XML_Node("key"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);

			//Either hash the public key or print the public key
			if(lockType==file::PUBLIC_UNLOCK)
			{
				trc2=os::smartXMLNode(new os::XML_Node("publicKey"),os::shared_type);
				auto tem=pbk->getN();
				tem->reduce();
				trc2->setData(tem->toString());
				trc1->addElement(trc2);
			}
			//Else, output a hash of the public key
			else
			{
				size_t tArrLen;
				os::smart_ptr<unsigned char> tempArr=pbk->getN()->getCompCharData(tArrLen);
				hsh=spf->hashData(tempArr.get(),tArrLen);
				trc2=os::smartXMLNode(new os::XML_Node("publicKeyHash"),os::shared_type);
				trc2->setData(hsh.toString());
				trc1->addElement(trc2);
			}

			trc2=os::smartXMLNode(new os::XML_Node("encryptedKey"),os::shared_type);
			if(lockType==file::DOUBLE_LOCK)
			{
				trc2->getDataList().push_back(num1->toString());
				trc2->getDataList().push_back(num2->toString());
			}
			else trc2->setData(num1->toString());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Data list
			std::vector<std::string> argList=generateArgumentList(head);
			trc1=os::smartXMLNode(new os::XML_Node("argList"),os::shared_type);
			for(unsigned int i=0;i<argList.size();++i)
				trc1->getDataList().push_back(argList[i]);
			encryHead->addElement(trc1);
        
			os::xml::writeNode(fileout,encryHead,0);

			os::smart_ptr<streamCipher> strm=spf->buildStream(raw_key.get(),keylen);
			if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			fileout<<'>';
			recursiveXMLPrinting(head,strm,argList,fileout);
		}
		catch(errorPointer e)
		{
			pbk->readUnlock();
			throw e;
		}
		catch(int e)
		{
			pbk->readUnlock();
			throw errorPointer(new customError("Indexed error","Error of type "+std::to_string((long long int)e)),os::shared_type);
		}
		catch(...) {
			pbk->readUnlock();
			throw errorPointer(new unknownErrorType(),os::shared_type);
		}
        pbk->readUnlock();
        return true;
    }
    bool EXML_Output(std::string path, os::smartXMLNode head, os::smart_ptr<number> publicKey,unsigned int pkAlgo,size_t pkSize,os::smart_ptr<streamPackageFrame> spf)
	{
		//Other types of encryption
		try
		{
			//Basic checks
			if(!head) throw errorPointer(new NULLDataError(),os::shared_type);
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			if(!publicKey) throw errorPointer(new NULLDataError(),os::shared_type);
			std::ofstream fileout(path,std::ios::binary);
			if(!fileout.good()) throw errorPointer(new fileOpenError(),os::shared_type);
			os::smart_ptr<publicKeyPackageFrame> pkframe=publicKeyTypeBank::singleton()->findPublicKey(pkAlgo);
			if(!pkframe) throw errorPointer(new illegalAlgorithmBind("Public key algorithm: "+std::to_string((long long unsigned int)pkAlgo)),os::shared_type);
			pkframe=pkframe->getCopy();
			pkframe->setKeySize((uint16_t)pkSize);

			//Check stream package
			if(!spf) spf=streamPackageTypeBank::singleton()->defaultPackage();
        
			//Output header
			fileout<<"<?exml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			os::smartXMLNode encryHead(new os::XML_Node("header"),os::shared_type);
        
			//Public key type
			os::smartXMLNode trc1(new os::XML_Node("public_key"),os::shared_type);
			os::smartXMLNode trc2(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(pkframe->algorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)pkframe->keySize()*32));
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("type"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)file::PRIVATE_UNLOCK));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Stream
			trc1=os::smartXMLNode(new os::XML_Node("stream"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->streamAlgorithmName());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);
        
			//Hash
			trc1=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("algo"),os::shared_type);
			trc2->setData(spf->hashAlgorithmName());
			trc1->addElement(trc2);
			trc2=os::smartXMLNode(new os::XML_Node("size"),os::shared_type);
			trc2->setData(std::to_string((long long unsigned int)spf->hashSize()*8));
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Generate key, and hash
			srand((unsigned)time(NULL));
			os::smart_ptr<unsigned char> randkey=os::smart_ptr<unsigned char>(new unsigned char[pkframe->keySize()*4],os::shared_type_array);
			memset(randkey.get(),0,pkframe->keySize()*4);
			for(uint16_t i=0;i<(pkframe->keySize()-1)*4;++i)
				randkey[i]=rand();
			os::smart_ptr<number> num=pkframe->convert(randkey.get(),pkframe->keySize()*4);
			num->reduce();
			size_t keylen;
			os::smart_ptr<unsigned char> raw_key=num->getCompCharData(keylen);
			if(!raw_key) throw errorPointer(new hashGenerationError(),os::shared_type);
			hash hsh=spf->hashData(raw_key.get(),keylen);
			num=pkframe->encode(num,publicKey);
			num->reduce();

			//Key
			trc1=os::smartXMLNode(new os::XML_Node("key"),os::shared_type);
			trc2=os::smartXMLNode(new os::XML_Node("hash"),os::shared_type);
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);
			
			size_t tArrLen;
			os::smart_ptr<unsigned char> tempArr=publicKey->getCompCharData(tArrLen);
			hsh=spf->hashData(tempArr.get(),tArrLen);
			trc2=os::smartXMLNode(new os::XML_Node("publicKeyHash"),os::shared_type);
			trc2->setData(hsh.toString());
			trc1->addElement(trc2);

			trc2=os::smartXMLNode(new os::XML_Node("encryptedKey"),os::shared_type);
			trc2->setData(num->toString());
			trc1->addElement(trc2);
			encryHead->addElement(trc1);

			//Data list
			std::vector<std::string> argList=generateArgumentList(head);
			trc1=os::smartXMLNode(new os::XML_Node("argList"),os::shared_type);
			for(unsigned int i=0;i<argList.size();++i)
				trc1->getDataList().push_back(argList[i]);
			encryHead->addElement(trc1);
        
			os::xml::writeNode(fileout,encryHead,0);

			os::smart_ptr<streamCipher> strm=spf->buildStream(raw_key.get(),keylen);
			if(!strm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			fileout<<'>';
			recursiveXMLPrinting(head,strm,argList,fileout);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string((long long int)e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return true;
	}
	//Decrypt with password
    os::smartXMLNode EXML_Input(std::string path, std::string password)
    {
		return EXML_Input(path,(unsigned char*) password.c_str(),password.length());
	}
	os::smartXMLNode EXML_Input(std::string path, unsigned char* symKey,size_t passwordLength)
	{
		os::smartXMLNode ret;
		try
		{
			//Basic checks
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			std::ifstream filein(path,std::ios::binary);
			if(!filein.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Password size check
			if(passwordLength>size::STREAM_SEED_MAX)
				throw errorPointer(new passwordLargeError(),os::shared_type);
			if(passwordLength<=0)
				throw errorPointer(new passwordSmallError(),os::shared_type);

			//Check header
			os::xml::readTillTag(filein);
			std::string temp = os::xml::readThroughTag(filein);
			if(temp != "?exml") throw errorPointer(new fileFormatError(),os::shared_type);

			//Parse header
			os::smartXMLNode enhead=os::xml::parseNode(filein);
			os::smartXMLNode trc1;
			os::smartXMLNode trc2;
			std::string streamID;
			std::string hashID;
			unsigned int hashSize;

			//Test ID
			if(!enhead) throw errorPointer(new fileOpenError(),os::shared_type);
			if(enhead->getID()!="header") throw errorPointer(new fileFormatError(),os::shared_type);

			//Public key
			auto fnd=enhead->findElement("public_key")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="none") throw errorPointer(new illegalAlgorithmBind("Expected NULL Public Key"),os::shared_type);

			//Stream
			fnd=enhead->findElement("stream")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				streamID=trc2->getData();

			//Hash
			fnd=enhead->findElement("hash")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashID=trc2->getData();

				//Size
				fnd=trc1->findElement("size")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashSize = std::stoi(trc2->getData())/8;

			//Bind encryption stream
			os::smart_ptr<streamPackageFrame> spf=streamPackageTypeBank::singleton()->findStream(streamID,hashID);
			if(!spf) throw errorPointer(new fileFormatError(),os::shared_type);
			spf=spf->getCopy();
			spf->setHashSize(hashSize);

			//Key manipulation
			fnd=enhead->findElement("key")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileOpenError(),os::shared_type);
			
				//Hash
				fnd=trc1->findElement("hash")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hash refHash=spf->hashData(symKey,passwordLength);
				hash compHash(refHash);
				compHash.fromString(trc2->getData());
				if(refHash!=compHash) throw errorPointer(new hashCompareError(),os::shared_type);

			//Arg list
			fnd=enhead->findElement("argList")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			std::vector<std::string> argList;
			if(trc1->getData()=="")
				argList=trc1->getDataList();
			else
				argList.push_back(trc1->getData());
			
			while(filein.get()!='>');
			ret=recursiveXMLBuilding(spf->buildStream(symKey,passwordLength),argList,filein);
		}
		catch(errorPointer e)
		{throw e;}
		catch(int e)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string((long long int)e)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}

        return ret;
    }
	//Decrypt with public key
    os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk,os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author)
    {
		os::smartXMLNode ret;
		try
		{
			//Basic checks
			if(os::check_exists(path) && os::is_directory(path)) throw errorPointer(new fileOpenError(),os::shared_type);
			std::ifstream filein(path,std::ios::binary);
			if(!filein.good()) throw errorPointer(new fileOpenError(),os::shared_type);
		
			//Check header
			os::xml::readTillTag(filein);
			std::string temp = os::xml::readThroughTag(filein);
			if(temp != "?exml")
				throw errorPointer(new fileFormatError(),os::shared_type);

			//Parse header
			os::smartXMLNode enhead=os::xml::parseNode(filein);
			os::smartXMLNode trc1;
			os::smartXMLNode trc2;
			std::string streamID;
			std::string hashID;
			unsigned int hashSize;

			//Test ID
			if(!enhead) throw errorPointer(new fileFormatError(),os::shared_type);
			if(enhead->getID()!="header") throw errorPointer(new fileFormatError(),os::shared_type);

			//Public key
			auto fnd=enhead->findElement("public_key")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);

				//Algorithm
				std::string algoName;
				fnd=trc1->findElement("algo")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				algoName=trc2->getData();

				//Size
				fnd=trc1->findElement("size")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				unsigned int pkSize=std::stoi(trc2->getData())/32;

				//Encryption type
				fnd=trc1->findElement("type")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				unsigned int pkType=std::stoi(trc2->getData());

				os::smart_ptr<publicKeyPackageFrame> pkframe=publicKeyTypeBank::singleton()->findPublicKey(algoName);
				if(!pkframe) throw errorPointer(new illegalAlgorithmBind("Public key algorithm: "+algoName),os::shared_type);
				pkframe=pkframe->getCopy();
				pkframe->setKeySize(pkSize);

			//Stream
			fnd=enhead->findElement("stream")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				streamID=trc2->getData();

			//Hash
			fnd=enhead->findElement("hash")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				//Algorithm
				fnd=trc1->findElement("algo")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashID=trc2->getData();

				//Size
				fnd=trc1->findElement("size")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				hashSize = std::stoi(trc2->getData())/8;

			//Bind encryption stream
			os::smart_ptr<streamPackageFrame> spf=streamPackageTypeBank::singleton()->findStream(streamID,hashID);
			if(!spf) throw errorPointer(new fileFormatError(),os::shared_type);
			spf=spf->getCopy();
			spf->setHashSize(hashSize);

			//Key manipulation
			fnd=enhead->findElement("key")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			if(trc1->getData()!="") throw errorPointer(new fileFormatError(),os::shared_type);
			
				size_t histInd;
				bool tLock;
				os::smart_ptr<number> readKey;

				//Read hash case (private and double unlock)
				if(pkType==file::PRIVATE_UNLOCK || pkType==file::DOUBLE_LOCK)
				{
					//Check public key
					if(!pbk) throw errorPointer(new NULLDataError(),os::shared_type);
					if(pbk->algorithm()!=pkframe->algorithm())
						throw errorPointer(new illegalAlgorithmBind(pbk->algorithmName()+" vs "+pkframe->algorithmName()),os::shared_type);
					if(pbk->size()!=pkframe->keySize())
						throw errorPointer(new illegalAlgorithmBind(std::to_string((long long unsigned int)pbk->size()*32)+" vs "+std::to_string((long long unsigned int)pkframe->keySize()*32)),os::shared_type);

					//Public key hash
					fnd=trc1->findElement("publicKeyHash")->first();
					if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
					trc2=&fnd;
					if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
					hash pkHash=spf->hashEmpty();
					pkHash.fromString(trc2->getData());

					if(!pbk->searchKey(pkHash,histInd,tLock)) throw errorPointer(new keyMissing(),os::shared_type);
				}
				else
				{
					fnd=trc1->findElement("publicKey")->first();
					if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
					trc2=&fnd;
					if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
					readKey=os::smart_ptr<number>(new number(),os::shared_type);
					readKey->fromString(trc2->getData());

					//Check key validity
					bool found=false;
					if(pbk)
					{
						if(pbk->searchKey(readKey,histInd,tLock))
							found=true;
					}
					if(kyBank)
					{
						author=kyBank->find(readKey,pkframe->algorithm(),pkframe->keySize());
						if(author) found = true;
					}
					if(!found)
						throw errorPointer(new keyMissing(),os::shared_type);
				}

				//Raw Key
				fnd=trc1->findElement("encryptedKey")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				os::smart_ptr<number> num1(new number(),os::shared_type);
				os::smart_ptr<number> num2;
				if(pkType==file::DOUBLE_LOCK)
				{
					num2=os::smart_ptr<number>(new number(),os::shared_type);
					if(trc2->getDataList().size()!=2) throw errorPointer(new fileFormatError(),os::shared_type);
					num1->fromString(trc2->getDataList()[0]);
					num2->fromString(trc2->getDataList()[1]);
					num1->reduce();
					num2->reduce();
				}
				else num1->fromString(trc2->getData());

				//Unlock with private key
				if(pkType==file::PRIVATE_UNLOCK)
				{
					num1=pbk->copyConvert(num1);
					num1=pbk->decode(num1,histInd);
					num1->reduce();
				}
				//Double lock
				else if(pkType==file::DOUBLE_LOCK)
				{
					if(!num2) throw errorPointer(new fileFormatError(),os::shared_type);
					num1=pbk->copyConvert(num1);
					num2=pbk->copyConvert(num2);

					num1=pbk->encode(num1,pbk->getOldN(histInd));
					num2=pbk->decode(num2,histInd);

					num1->reduce();
					num2->reduce();
				}
				//Public key unlock
				else
				{
					if(!readKey) throw errorPointer(new fileFormatError(),os::shared_type);
					readKey=pkframe->convert(readKey->data(),readKey->size());
					num1=pkframe->convert(num1->data(),num1->size());
					num1=pkframe->encode(num1,readKey);
					num1->reduce();
				}
				

				//Hash
				fnd=trc1->findElement("hash")->first();
				if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
				trc2=&fnd;
				if(!trc2) throw errorPointer(new fileFormatError(),os::shared_type);
				size_t keylen;
				os::smart_ptr<unsigned char> raw_key;
				if(pkType==file::DOUBLE_LOCK)
				{
					os::smart_ptr<unsigned char> tarr=num1->getCompCharData(keylen);
					raw_key=os::smart_ptr<unsigned char>(new unsigned char[keylen*2],os::shared_type);
					memcpy(raw_key.get(),tarr.get(),keylen);
					tarr=num2->getCompCharData(keylen);
					memcpy(raw_key.get()+keylen,tarr.get(),keylen);
					keylen=keylen*2;
				}
				else raw_key=num1->getCompCharData(keylen);
				if(!raw_key) throw errorPointer(new hashGenerationError(),os::shared_type);

				hash refHash=spf->hashData(raw_key.get(),keylen);
				hash compHash(refHash);
				compHash.fromString(trc2->getData());
				if(refHash!=compHash)
					throw errorPointer(new hashCompareError(),os::shared_type);

			//Arg list
			fnd=enhead->findElement("argList")->first();
			if(!fnd) throw errorPointer(new fileFormatError(),os::shared_type);
			trc1=&fnd;
			if(!trc1) throw errorPointer(new fileFormatError(),os::shared_type);
			std::vector<std::string> argList;
			if(trc1->getData()=="")
				argList=trc1->getDataList();
			else
				argList.push_back(trc1->getData());

			while(filein.get()!='>');

			ret=ret=recursiveXMLBuilding(spf->buildStream((unsigned char*) raw_key.get(),keylen),argList,filein);
		}
		catch(errorPointer e1)
		{throw e1;}
		catch(int e2)
		{throw errorPointer(new customError("Indexed error","Error of type "+std::to_string((long long int)e2)),os::shared_type);}
		catch(...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
        
        return ret;
    }

	//Call master EXML public key decryptor
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<publicKey> pbk)
	{
		os::smart_ptr<nodeGroup> aut;
		return EXML_Input(path, pbk,NULL,aut);
	}
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank)
	{
		os::smart_ptr<nodeGroup> aut;
		return EXML_Input(path, NULL,kyBank,aut);
	}
	os::smartXMLNode EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author)
	{return EXML_Input(path, NULL,kyBank,author);}
}

#endif

///@endcond