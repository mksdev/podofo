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

#include "PdfInfo.h"

#include "PdfDate.h"
#include "PdfDictionary.h"
#include "PdfString.h"

#define PRODUCER_STRING "PoDoFo - http://podofo.sf.net"

namespace PoDoFo {

PdfInfo::PdfInfo( PdfVecObjects* pParent )
    : PdfIElement( NULL, pParent )
{
    Init( false );
}

PdfInfo::PdfInfo( PdfObject* pObject )
    : PdfIElement( NULL, pObject )
{
    Init( true );
}

PdfInfo::~PdfInfo()
{
}

void PdfInfo::Init( bool bModify )
{
    PdfDate   date;
    PdfString str;

    date.ToString( str );
    
    GetObject()->GetDictionary().AddKey( bModify ? "ModDate" : "CreationDate", str );
    GetObject()->GetDictionary().AddKey( "Producer", PdfString( PRODUCER_STRING) );
}

const PdfString & PdfInfo::GetStringFromInfoDict( const PdfName & rName ) const
{
    const PdfVariant* pVar = GetObject()->GetDictionary().GetKey( rName );
    
    return pVar && pVar->IsString() ? pVar->GetString() : PdfString::StringNull;
}

void PdfInfo::SetAuthor( const PdfString & sAuthor )
{
    GetObject()->GetDictionary().AddKey( "Author", sAuthor );
}

void PdfInfo::SetCreator( const PdfString & sCreator )
{
    GetObject()->GetDictionary().AddKey( "Creator", sCreator );
}

void PdfInfo::SetKeywords( const PdfString & sKeywords )
{
    GetObject()->GetDictionary().AddKey( "Keywords", sKeywords );
}

void PdfInfo::SetSubject( const PdfString & sSubject )
{
    GetObject()->GetDictionary().AddKey( "Subject", sSubject );
}

void PdfInfo::SetTitle( const PdfString & sTitle )
{
    GetObject()->GetDictionary().AddKey( "Title", sTitle );
}

};
