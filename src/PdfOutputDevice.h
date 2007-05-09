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

#ifndef _PDF_OUTPUT_DEVICE_H_
#define _PDF_OUTPUT_DEVICE_H_

#include <cstdarg>
#include <ostream>
#include <stack>

#include "PdfDefines.h"
#include "PdfLocale.h"
#include "PdfError.h"

namespace PoDoFo {

/** This class provides an output device which operates 
 *  either on a file or on a buffer in memory.
 *  Additionally it can count the bytes written to the device.
 *
 *  This class is suitable for inheritance to provide output 
 *  devices of your own for PoDoFo.
 *  Just overide the required virtual methods.
 */
class PODOFO_API PdfOutputDevice {
 public:

    /** Construct a new PdfOutputDevice that does not write any data. Only the length
     *  of the data is counted.
     *
     */
    PdfOutputDevice();

    /** Construct a new PdfOutputDevice that writes all data to a file.
     *
     *  \param pszFilename path to a file that will be opened and all data
     *                     is written to this file.
     */
    PdfOutputDevice( const char* pszFilename );

    /** Construct a new PdfOutputDevice that writes all data to a memory buffer.
     *  The buffer will not be owned by this object and has to be allocated before.
     *
     *  \param pBuffer a buffer in memory
     *  \param lLen the length of the buffer in memory
     */
    PdfOutputDevice( char* pBuffer, long lLen );

    /** Construct a new PdfOutputDevice that writes all data to a std::ostream.
     *
     *  \param pOutStream write to this std::ostream
     */
    PdfOutputDevice( const std::ostream* pOutStream );

    /** Destruct the PdfOutputDevice object and close any open files.
     */
    virtual ~PdfOutputDevice();

    /** The number of bytes written to this object.
     *  \returns the number of bytes written to this object.
     *  
     *  \see Init
     */
    virtual inline unsigned long GetLength() const;

    /** Write to the PdfOutputDevice. Usage is as the usage of printf.
     * 
     *  \param writer The object doing the writing. If you have ordered write
     *         checking enabled, this must be the object on the top of the writer
     *         stack or an exception will be thrown.
     *  \param pszFormat a format string as you would use it with printf
     *  \returns ErrOk on success
     *
     *  \see Write
     */
    virtual void Print( const void* writer, const char* pszFormat, ... );

    /** Write data to the buffer. Use this call instead of Print if you 
     *  want to write binary data to the PdfOutputDevice.
     *
     *  \param writer The object doing the writing. If you have ordered write
     *         checking enabled, this must be the object on the top of the writer
     *         stack or an exception will be thrown.
     *  \param pBuffer a pointer to the data buffer
     *  \param lLen write lLen bytes of pBuffer to the PdfOutputDevice
     *  \returns ErrOk on success
     * 
     *  \see Print
     */
    virtual void Write( const void* writer, const char* pBuffer, long lLen );

    /**
     * Overload of Write( const void* writer, const char* pBufer, long lLen) that
     * passes 0 for `writer' and is intended for use only on unlocked output devices.
     *
     * \see Write
     */
    inline void Write( const char* pBuffer, long lLen );

    /** Seek the device to the position offset from the begining
     *  \param writer The object doing the writing. If you have ordered write
     *         checking enabled, this must be the object on the top of the writer
     *         stack or an exception will be thrown.
     *  \param offset from the beginning of the file
     */
    virtual void Seek( const void* writer, size_t offset );

    /**
     * Overload of Seek( const void* writer, size_t offset ) that passes 0 for
     * `writer' and works only on unlocked output devices.
     */
    inline void Seek( size_t offset );


    /** Flush the output files buffer to disk if this devices
     *  operates on a disk.
     */
    virtual void Flush() const;

    /**
     * If ordered write checking was enabled, push an object to the top of the writer
     * stack. Only this object is permitted to write to the output device until it is
     * popped from the stack. The object must specify the last object on the stack
     * (or NULL if there is none) to prevent one from simply unwittingly replacing
     * another.
     *
     * You don't need to use this facility for objects that write themselves out
     * all in one go. It's here to protect objects that're "held open" for more
     * data to be appended, such as stream objects.
     *
     * If ordered write checking is not on, this inlines to nothing.
     *
     * \param lastWriter Pointer to the object that was last writing (ie the
     *        object on the top of the stack). If this doesn't match
     *        an exception will be thrown. If no last writer exists, pass 0.
     * \param writer Pointer to the object that will be writing next.
     */
    inline void PushWriter(const void* lastWriter, const void* nextWriter);

    /**
     * If ordered write checking was enabled, pop the last writer from the top
     * of the stack. For sanity checking, you must pass a pointer to that
     * writer. An exception will be thrown if it wasn't on the top of the
     * stack.
     *
     * \param lastWriter Pointer to the object that was last writing (ie the
     *        object on the top of the stack). If this doesn't match
     *        an exception will be thrown.
     */
    inline void PopWriter(const void* lastWriter);

    /** Check that the passed writer is the top of the stack or the stack is empty.
     *  If the stack is non-empty and `writer'is not on top, throw.
     *
     * \param writer Pointer to the object that should be doing the writing
     *        according to the stack.
     */
    inline void CheckWriter(const void* writer);

 private: 
    /** Initialize all private members
     */
    void Init();

 protected:
    unsigned long m_ulLength;

 private:
    FILE*         m_hFile;
    char*         m_pBuffer;
    unsigned long m_lBufferLen;

    std::ostream*  m_pStream;

    // used for ordered write checking. Otherwise, it's useless, but it hardly
    // uses any RAM and we don't create that many PdfOutputDevice instances, so
    // it's worth the waste to avoid preprocessor macros changing the object layout.
    std::stack<const void*> m_writers;
};

unsigned long PdfOutputDevice::GetLength() const
{
    return m_ulLength;
}

void PdfOutputDevice::Write( const char* pBuffer, long lLen )
{
    Write(NULL, pBuffer, lLen);
}

void PdfOutputDevice::Seek( size_t offset )
{
    Seek(NULL, offset);
}

#if PODOFO_CHECK_ORDERED_WRITES
void PdfOutputDevice::PushWriter(const void* lastWriter, const void* nextWriter)
{
    if (lastWriter)
    {
        PODOFO_RAISE_LOGIC_IF( m_writers.top() != lastWriter,
                "Write lock order violation in acquisition - wrong last writer");
    }
    else
    {
        PODOFO_RAISE_LOGIC_IF( !m_writers.empty(),
                "Write lock order violation in acquisition - claimed no writer incorrectly");
    }
    m_writers.push(nextWriter);
}

void PdfOutputDevice::PopWriter(const void* lastWriter)
{
    PODOFO_RAISE_LOGIC_IF( m_writers.top() == 0,
            "Write lock order violation in release - writer stack underflow");
    PODOFO_RAISE_LOGIC_IF( m_writers.top() != lastWriter,
            "Write lock order violation in release - wrong last writer");
    m_writers.pop();
}

void PdfOutputDevice::CheckWriter(const void* writer)
{
    if (!m_writers.empty() && m_writers.top() != writer)
        PODOFO_RAISE_ERROR_INFO( ePdfError_InternalLogic,
                "Write order lock violation in check - wrong writer");
}

#else
void PdfOutputDevice::PopWriter(const void*) { }
void PdfOutputDevice::PushWriter(const void*,const void*) { }
void PdfOutputDevice::CheckWriter(const void*) { }
#endif

};

#endif // _PDF_OUTPUT_DEVICE_H_

