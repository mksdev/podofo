
#ifndef PKIBOX_UTILS_FILE_H
#define PKIBOX_UTILS_FILE_H

#include <string>
#include <fstream>

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;

		//! This class encapsulates a file on disk. 
		/*!
			This class simplifies file handling. It has the operations of loading and saving files
			from/into ByteArray.
		*/
		class File  
		{
		public:

			//! Default constructor. Creates an empty File object.
			File();

			//! Construct a File object from a filename according to the flags provided.
			/*!
				\param const std::string &strFilePath
				\param std::ios_base::openmode Openmode
			*/
			File(const std::string &strFilePath, std::ios_base::openmode Openmode);

			//! Destructor
			virtual ~File();

			//! Returns the total number of bytes of file.
			/*!
				\return unsigned int
			*/
			unsigned int GetLength() /* throw (Exception) */;

			//! Reads nCount number of bytes from file into buffer pBuff.
			/*!
				\param char *pBuff
				\param unsigned int nCount
			*/
			void Read(char *pBuff, unsigned int nCount) /* throw (Exception) */ ;

			//! Writes nCount number of bytes from buffer pBuff into file.
			/*!
				\param const char *pBuff
				\param unsigned int nCount
			*/
			void Write(const char *pBuff, unsigned int nCount) /* throw (Exception) */ ;

			//! Clears the contents of the file. 
			void Clear();

			//! Loads the contents of a file specified by Filename into the ByteArray. 
			/*!
				\param const std::string& Filename
				\return ByteArray 
			*/
			static ByteArray Load(const std::string& Filename) /* throw (Exception) */;

			//! Saves the ByteArray into the File specified by filename.
			/*!
				\param const std::string& Filename
				\param const ByteArray &Bytes
			*/
			static void Save(const std::string& Filename, const ByteArray &Bytes) /* throw (Exception) */;

			//! Deletes a file specified by filename.
			/*!
				\param const std::string& Filename
				\return bool 
			*/
			static bool Remove(const std::string& Filename) /* throw (Exception) */;

			//! Checks the existence of file on disk.
			/*!
				\param const std::string& Filename
				\return bool 
			*/
			static bool Exists(const std::string& Filename) /* throw (Exception) */;
#ifdef WIN32
			//! Retrieves the filename of the selected file. 
			/*!
				\return std::string
			*/
			std::string GetFileName() const ;

			//! Retrieves the title of the selected file. 
			/*!
				\return std::string
			*/
			std::string GetFileTitle() const ;

			//! Retrieves the full file path of the selected file.
			/*!
				\return std::string
			*/
			std::string GetFileDirectory() const ;
#endif
		private:
			unsigned int			m_uiLength;		// Length of file
			std::string				m_strFilePath;	// Complete name of file i.e. name + path
			std::ios_base::openmode	m_Openmode;		// File open flags.
			std::fstream			m_File;			// Underlying stream object

		};
	}
}

#endif // PKIBOX_UTILS_FILE_H


