/***************************************************************************
 *   Copyright (C) 2010 by Dominik Seichter                                *
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

#include "PdfPainterMM.h"

#include "base/PdfDefinesPrivate.h"

namespace PoDoFo {

PdfPainterMM::PdfPainterMM()
{
}

/* Defining the virtual destructor here rather than in the header
 * ensures that the vtable gets output correctly by all compilers.
 */
PdfPainterMM::~PdfPainterMM()
{
}

void PdfPainterMM::SetStrokeWidthMM( long lWidth )
{
    this->SetStrokeWidth( static_cast<double>(lWidth) * CONVERSION_CONSTANT );
}

void PdfPainterMM::DrawLineMM( long lStartX, long lStartY, long lEndX, long lEndY )
{
    this->DrawLine( static_cast<double>(lStartX) * CONVERSION_CONSTANT,
                    static_cast<double>(lStartY) * CONVERSION_CONSTANT,
                    static_cast<double>(lEndX)   * CONVERSION_CONSTANT,
                    static_cast<double>(lEndY)   * CONVERSION_CONSTANT );
}

void PdfPainterMM::RectangleMM( long lX, long lY, long lWidth, long lHeight )
{
    this->Rectangle( static_cast<double>(lX)      * CONVERSION_CONSTANT,
                     static_cast<double>(lY)      * CONVERSION_CONSTANT,
                     static_cast<double>(lWidth)  * CONVERSION_CONSTANT,
                     static_cast<double>(lHeight) * CONVERSION_CONSTANT );
}

void PdfPainterMM::EllipseMM( long lX, long lY, long lWidth, long lHeight )
{
    this->Ellipse( static_cast<double>(lX)      * CONVERSION_CONSTANT,
                   static_cast<double>(lY)      * CONVERSION_CONSTANT,
                   static_cast<double>(lWidth)  * CONVERSION_CONSTANT,
                   static_cast<double>(lHeight) * CONVERSION_CONSTANT );
}

void PdfPainterMM::DrawTextMM( long lX, long lY, const PdfString & sText)
{
    this->DrawText( static_cast<double>(lX) * CONVERSION_CONSTANT,
                    static_cast<double>(lY) * CONVERSION_CONSTANT,
                    sText );
}

void PdfPainterMM::DrawTextMM( long lX, long lY, const PdfString & sText, long lLen )
{
   this->DrawText( static_cast<double>(lX) * CONVERSION_CONSTANT,
                   static_cast<double>(lY) * CONVERSION_CONSTANT,
                   sText, lLen );
}

void PdfPainterMM::DrawImageMM( long lX, long lY, PdfImage* pObject, double dScaleX, double dScaleY )
{
   this->DrawImage( static_cast<double>(lX) * CONVERSION_CONSTANT,
                    static_cast<double>(lY) * CONVERSION_CONSTANT,
                    pObject, dScaleX, dScaleY );
}

void PdfPainterMM::DrawXObjectMM( long lX, long lY, PdfXObject* pObject, double dScaleX, double dScaleY )
{
   this->DrawXObject( static_cast<double>(lX) * CONVERSION_CONSTANT,
                      static_cast<double>(lY) * CONVERSION_CONSTANT,
                      pObject, dScaleX, dScaleY );
}

void PdfPainterMM::LineToMM( long lX, long lY )
{
    this->LineTo( static_cast<double>(lX) * CONVERSION_CONSTANT,
                  static_cast<double>(lY) * CONVERSION_CONSTANT );
}

void PdfPainterMM::MoveToMM( long lX, long lY )
{
    this->MoveTo( static_cast<double>(lX) * CONVERSION_CONSTANT,
                  static_cast<double>(lY) * CONVERSION_CONSTANT );
}

};
