/***************************************************************************
 *   Copyright (C) 2006 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _PDF_FILE_SPEC_H_
#define _PDF_FILE_SPEC_H_

#include "PdfDefines.h"

#include "PdfElement.h"

#include "PdfString.h"

namespace PoDoFo {

/**
 *  A file specification is used in the PDF file to referr to another file.
 *  The other file can be a file outside of the PDF or can be embedded into
 *  the PDF file itself.
 *
 *  A file specification may be a plain PdfString or a dictionary.
 *
 *  LIMITATIONS
 *  -----------
 *  - Multi-byte-per-character file specifications are not currently
 *    supported by PdfFileSpec.
 *  - Currently only the `F' key for a platform-independent file name
 *    is used. The Mac, Unix and DOS keys are not examined, nor are the
 *    associated entries in the EF dictionary.
 */
class PODOFO_API PdfFileSpec : public PdfElement {
 public:
    /**
     * Create a new PdfFileSpec that refers to a local file system path.
     * A new indirect object will be created in `pParent' to store it.
     * The dictionary form will always be created.
     *
     * \param pszFilename The local file path
     * \param bEmbed Embed the file referenced by the file spec in the PDF as a stream?
     * \param pParent The PdfVecObjects to create the file spec object in.
     */
    PdfFileSpec( const char* pszFilename, bool bEmbed, PdfVecObjects* pParent );

    /**
     * Initialize a PdfFileSpec that works on an existing variant containing
     * file spec data. Either string or dictionary forms of the file spec are
     * permitted.
     */
    PdfFileSpec( PdfVariant* pObject );

    /** \returns the filename of this file specification.
     *           if no general name is available 
     *           it will try the Unix, Mac and DOS keys too.
     */
    const PdfString & GetFilename() const;

 private:
    PdfFileSpec( const PdfFileSpec& );
    PdfFileSpec& operator=( const PdfFileSpec& );

    /** Create a file specification string from a filename
     *  \param pszFilename filename 
     *  \returns a file specification string
     */
    PdfString CreateFileSpecification( const char* pszFilename ) const;

    /** Embedd a file into a stream object
     *  \param pStream write the file to this objects stream
     *  \param pszFilename the file to embedd
     */
    void EmbedFile( PdfObject* pStream, const char* pszFilename ) const;
};

};

#endif // _PDF_FILE_SPEC_H_

