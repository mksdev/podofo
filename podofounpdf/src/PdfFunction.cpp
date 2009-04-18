/***************************************************************************
 *   Copyright (C) 2007 by Dominik Seichter                                *
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

#include "PdfFunction.h"

#include "PdfArray.h"
#include "PdfDictionary.h"

namespace PoDoFo {

PdfFunction::PdfFunction( EPdfFunctionType eType, const PdfArray & rDomain, PdfVecObjects* pParent )
    : PdfElement( NULL, pParent )
{
    Init( eType, rDomain );
}

PdfFunction::PdfFunction( EPdfFunctionType eType, const PdfArray & rDomain, PdfDocument* pParent )
    : PdfElement( NULL, pParent )
{
    Init( eType, rDomain );
}

PdfFunction::~PdfFunction()
{

}

void PdfFunction::Init( EPdfFunctionType eType, const PdfArray & rDomain )
{
    m_pObject->GetDictionary().AddKey( PdfName("FunctionType"), static_cast<long long>(eType) );
    m_pObject->GetDictionary().AddKey( PdfName("Domain"), rDomain );

}

/////////////////////////////////////////////////////////////////////////////
PdfExponentialFunction::PdfExponentialFunction( const PdfArray & rDomain, const PdfArray & rC0, const PdfArray & rC1, double dExponent, PdfVecObjects* pParent )
    : PdfFunction( ePdfFunctionType_Exponential, rDomain, pParent )
{
    Init( rC0, rC1, dExponent );
}

PdfExponentialFunction::PdfExponentialFunction( const PdfArray & rDomain, const PdfArray & rC0, const PdfArray & rC1, double dExponent, PdfDocument* pParent )
    : PdfFunction( ePdfFunctionType_Exponential, rDomain, pParent )
{
    Init( rC0, rC1, dExponent );
}

void PdfExponentialFunction::Init( const PdfArray & rC0, const PdfArray & rC1, double dExponent )
{
    this->GetObject()->GetDictionary().AddKey( PdfName("C0"), rC0 );
    this->GetObject()->GetDictionary().AddKey( PdfName("C1"), rC1 );
    this->GetObject()->GetDictionary().AddKey( PdfName("N"), dExponent );
}

/////////////////////////////////////////////////////////////////////////////

PdfStitchingFunction::PdfStitchingFunction( const PdfFunction::List & rlstFunctions, const PdfArray & rDomain, const PdfArray & rBounds, const PdfArray & rEncode, PdfVecObjects* pParent )
    : PdfFunction( ePdfFunctionType_Stitching, rDomain, pParent )
{
    Init( rlstFunctions, rBounds, rEncode );
}

PdfStitchingFunction::PdfStitchingFunction( const PdfFunction::List & rlstFunctions, const PdfArray & rDomain, const PdfArray & rBounds, const PdfArray & rEncode, PdfDocument* pParent )
    : PdfFunction( ePdfFunctionType_Stitching, rDomain, pParent )
{
    Init( rlstFunctions, rBounds, rEncode );
}

void PdfStitchingFunction::Init( const PdfFunction::List & rlstFunctions, const PdfArray & rBounds, const PdfArray & rEncode )
{
    PdfArray                          functions;
    PdfFunction::List::const_iterator it = rlstFunctions.begin();

    functions.reserve( rlstFunctions.size() );

    while( it != rlstFunctions.end() )
    {
        functions.push_back( (*it).GetObject()->Reference() );
        ++it;
    }
    
    this->GetObject()->GetDictionary().AddKey( PdfName("Functions"), functions );
    this->GetObject()->GetDictionary().AddKey( PdfName("Bounds"), rBounds );
    this->GetObject()->GetDictionary().AddKey( PdfName("Encode"), rEncode );
}

};
