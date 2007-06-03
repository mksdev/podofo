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

#include "PdfFileSpec.h"

#include "PdfDictionary.h"
#include "PdfInputStream.h"
#include "PdfObject.h"
#include "PdfStream.h"

#include <sstream>

namespace PoDoFo {

PdfFileSpec::PdfFileSpec( const char* pszFilename, bool bEmbedd, PdfVecObjects* pParent )
    : PdfElement( "Filespec", pParent )
{
    GetObject()->GetDictionary().AddKey( "F", this->CreateFileSpecification( pszFilename ) );

    if( bEmbedd ) 
    {
        PdfDictionary ef;

        PdfObject * const pEmbeddedStream = pParent->CreateObject( "EmbeddedFile" );
        this->EmbedFile( pEmbeddedStream, pszFilename );

        ef.AddKey( "F",  pEmbeddedStream->Reference() );

        GetObject()->GetDictionary().AddKey( "EF", ef );
    }
}

// TODO: handle multi-byte file spec strings
// TODO we fail to verify that the passed data looks like a sane filespec.
PdfFileSpec::PdfFileSpec( PdfVariant* pVariant )
    : PdfElement( "Filespec", pVariant )
{
    if ( !(GetObject()->IsDictionary() || GetObject()->IsString()) )
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType, "Argument must be a string or dictionary");
    if (pVariant->IsString())
    {
        // We only support PdfDictionary file specs, so convert the passed spec
        // to the dictionary form.
        PdfDictionary d;
        d.AddKey( PdfName("F"), pVariant);
        GetObject() = d;
    }
}

PdfString PdfFileSpec::CreateFileSpecification( const char* pszFilename ) const
{
    std::ostringstream str;
    int                nLen = strlen( pszFilename );

    // FIXME: This doesn't reliably produce a platform independent file spec,
    // and may damage file names that contain characters (like a :) that are
    // legal on a particular platform.
    for( int i=0;i<nLen;i++ ) 
    {
        if( pszFilename[i] == ':' || pszFilename[i] == '\\' ) 
            str.put( '/' );
        else 
            str.put( pszFilename[i] );
    }

    return PdfString( str.str() );
}

void PdfFileSpec::EmbedFile( PdfObject* pStream, const char* pszFilename ) const
{
    PdfFileInputStream stream( pszFilename );
    pStream->GetStream()->Set( &stream );

    // Add additional information about the embedded file to the stream
    PdfDictionary params;
    params.AddKey( "Size", stream.GetFileLength() );
    // TODO: CreationDate and ModDate
    pStream->GetDictionary().AddKey("Params", params );
}

const PdfString & PdfFileSpec::GetFilename() const
{
    PODOFO_RAISE_LOGIC_IF(
            !GetObject()->GetDictionary().HasKey( "F" ),
            "PdfFileSpec's object must be a dictionary");
    return GetObject()->GetDictionary().GetKey( "F" )->GetString();
}


};
