#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Provides functions for reading (writing is WIP currently) of Java
objects serialized by ObjectOutputStream. This form of object
representation is a standard data interchange format in Java world.

javaobj module exposes an API familiar to users of the standard modules
such as marshal, pickle and json.

See: http://download.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html
"""

import io
import struct

try:
    import logging
except ImportError:
    def log_debug(message, ident=0):
        pass
    def log_error(message, ident=0):
        pass
else:
    _log = logging.getLogger(__name__)
    def log_debug(message, ident=0):
        _log.debug(" " * (ident * 2) + str(message))
    def log_error(message, ident=0):
        _log.error(" " * (ident * 2) + str(message))

__version__ = "$Revision: 20 $"


def load(file_object, *args):
    """
    Deserializes Java primitive data and objects serialized by ObjectOutputStream
    from a file-like object.
    """
    marshaller = JavaObjectUnmarshaller(file_object)
    for t in args:
        marshaller.add_transformer(t)
    marshaller.add_transformer(DefaultObjectTransformer())
    return marshaller.readObject()


def load_all(file_object):
    marshaller = JavaObjectUnmarshaller(file_object)
    marshaller.add_transformer(DefaultObjectTransformer())
    
    res = []
    while marshaller.data_left:
        res.append(marshaller.readObject())
    return res


def loads(string, *args):
    """
    Deserializes Java objects and primitive data serialized by ObjectOutputStream
    from a string.
    """
    f = io.StringIO(string)
    marshaller = JavaObjectUnmarshaller(f)
    for t in args:
        marshaller.add_transformer(t)
    marshaller.add_transformer(DefaultObjectTransformer())
    return marshaller.readObject()


def dumps(object, *args):
    """
    Serializes Java primitive data and objects unmarshaled by load(s) before into string.
    """
    marshaller = JavaObjectMarshaller()
    for t in args:
        marshaller.add_transformer(t)
    return marshaller.dump(object)


class JavaClass(object):
    def __init__(self):
        self.name = None
        self.serialVersionUID = None
        self.flags = None
        self.handle = None
        self.fields_names = []
        self.fields_types = []
        self.superclass = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "[%s:0x%X]" % (self.name, self.serialVersionUID)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.name == other.name and
                self.serialVersionUID == other.serialVersionUID and
                self.flags == other.flags and
                self.fields_names == other.fields_names and
                self.fields_types == other.fields_types and
                self.superclass == other.superclass)


class JavaObject(object):

    def __init__(self):
        self.classdesc = None
        self.annotations = []

    def get_class(self):
        return self.classdesc

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        name = "UNKNOWN"
        if self.classdesc:
            name = self.classdesc.name
        return "<javaobj:%s>" % name

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        res = (self.classdesc == other.classdesc and
                self.annotations == other.annotations)
        for name in self.classdesc.fields_names:
            res = (res and 
                   getattr(self, name) == getattr(other, name))
        return res

    def copy(self, new_object):
        new_object.classdesc = self.classdesc
        new_object.annotations = self.annotations

        for name in self.classdesc.fields_names:
            new_object.__setattr__(name, getattr(self, name))


class JavaString(str):
    def __init__(self, *args, **kwargs):
        str.__init__(self, *args, **kwargs)

    def __eq__(self, other):
        if not isinstance(other, str):
            return False
        return str.__eq__(self, other)


class JavaEnum(JavaObject):
    def __init__(self, constant=None):
        super(JavaEnum, self).__init__()
        self.constant = constant


class JavaArray(list, JavaObject):
    def __init__(self, classdesc=None):
        list.__init__(self)
        JavaObject.__init__(self)
        self.classdesc = classdesc


class JavaObjectConstants:

    STREAM_MAGIC = 0xaced
    STREAM_VERSION = 0x05

    TC_NULL = 0x70
    TC_REFERENCE = 0x71
    TC_CLASSDESC = 0x72
    TC_OBJECT = 0x73
    TC_STRING = 0x74
    TC_ARRAY = 0x75
    TC_CLASS = 0x76
    TC_BLOCKDATA = 0x77
    TC_ENDBLOCKDATA = 0x78
    TC_RESET = 0x79
    TC_BLOCKDATALONG = 0x7A
    TC_EXCEPTION = 0x7B
    TC_LONGSTRING = 0x7C
    TC_PROXYCLASSDESC = 0x7D
    TC_ENUM = 0x7E
    TC_MAX = 0x7E

    # classDescFlags
    SC_WRITE_METHOD = 0x01 # if SC_SERIALIZABLE
    SC_BLOCK_DATA = 0x08   # if SC_EXTERNALIZABLE
    SC_SERIALIZABLE = 0x02
    SC_EXTERNALIZABLE = 0x04
    SC_ENUM = 0x10

    # type definition chars (typecode)
    TYPE_BYTE = 'B'     # 0x42
    TYPE_CHAR = 'C'
    TYPE_DOUBLE = 'D'   # 0x44
    TYPE_FLOAT = 'F'    # 0x46
    TYPE_INTEGER = 'I'  # 0x49
    TYPE_LONG = 'J'     # 0x4A
    TYPE_SHORT = 'S'    # 0x53
    TYPE_BOOLEAN = 'Z'  # 0x5A
    TYPE_OBJECT = 'L'   # 0x4C
    TYPE_ARRAY = '['    # 0x5B

    # list of supported typecodes listed above
    TYPECODES_LIST = [
            # primitive types
            TYPE_BYTE,
            TYPE_CHAR,
            TYPE_DOUBLE,
            TYPE_FLOAT,
            TYPE_INTEGER,
            TYPE_LONG,
            TYPE_SHORT,
            TYPE_BOOLEAN,
            # object types
            TYPE_OBJECT,
            TYPE_ARRAY ]

    BASE_REFERENCE_IDX = 0x7E0000


class JavaObjectUnmarshaller(JavaObjectConstants):

    def __init__(self, stream=None):
        self.opmap = {
            self.TC_NULL: self.do_null,
            self.TC_CLASSDESC: self.do_classdesc,
            self.TC_OBJECT: self.do_object,
            self.TC_STRING: self.do_string,
            self.TC_LONGSTRING: self.do_string_long,
            self.TC_ARRAY: self.do_array,
            self.TC_CLASS: self.do_class,
            self.TC_BLOCKDATA: self.do_blockdata,
            self.TC_BLOCKDATALONG: self.do_blockdata_long,
            self.TC_REFERENCE: self.do_reference,
            self.TC_ENUM: self.do_enum,
            self.TC_ENDBLOCKDATA: self.do_null, # note that we are reusing of do_null
        }
        self.current_object = None
        self.reference_counter = 0
        self.references = []
        self.object_stream = stream
        self._readStreamHeader()
        self.object_transformers = []
        self.data_left = True

    def readObject(self):
        try:
            opcode, res = self._read_and_exec_opcode(ident=0)    # TODO: add expects

            position_bak = self.object_stream.tell()
            the_rest = self.object_stream.read()
            if len(the_rest):
                log_error("Warning!!!!: Stream still has %s bytes left. Enable debug mode of logging to see the hexdump." % len(the_rest))
                log_debug(self._create_hexdump(the_rest, position_bak))
                self.data_left = True
            else:
                log_debug("Java Object unmarshalled succesfully!")
                self.data_left = False
            self.object_stream.seek(position_bak)

            return res
        except Exception as e:
            self._oops_dump_state()
            raise

    def add_transformer(self, transformer):
        self.object_transformers.append(transformer)

    def _readStreamHeader(self):
        (magic, version) = self._readStruct(">HH")
        if magic != self.STREAM_MAGIC or version != self.STREAM_VERSION:
            raise IOError("The stream is not java serialized object. Invalid stream header: %04X%04X" % (magic, version))

    def _read_and_exec_opcode(self, ident=0, expect=None):
        position = self.object_stream.tell()
        (opid, ) = self._readStruct(">B")
        log_debug("OpCode: 0x%X (at offset: 0x%X)" % (opid, position), ident)
        if expect and opid not in expect:
            raise IOError("Unexpected opcode 0x%X" % opid)
        handler = self.opmap.get(opid)
        if not handler:
            raise RuntimeError("Unknown OpCode in the stream: 0x%x" % opid)
        return (opid, handler(ident=ident))

    def _readStruct(self, unpack):
        length = struct.calcsize(unpack)
        ba = self.object_stream.read(length)
        if len(ba) != length:
            raise RuntimeError("Stream has been ended unexpectedly while unmarshaling. (%d vs %d)" % (len(ba), length))
        return struct.unpack(unpack, ba)

    def _readString(self, mod="H"):
        (length, ) = self._readStruct(">" + mod)
        ba = self.object_stream.read(length)
        return ba

    def do_classdesc(self, parent=None, ident=0):
        # TC_CLASSDESC className serialVersionUID newHandle classDescInfo
        # classDescInfo:
        #   classDescFlags fields classAnnotation superClassDesc
        # classDescFlags:
        #   (byte)                  // Defined in Terminal Symbols and Constants
        # fields:
        #   (short)<count>  fieldDesc[count]

        # fieldDesc:
        #   primitiveDesc
        #   objectDesc
        # primitiveDesc:
        #   prim_typecode fieldName
        # objectDesc:
        #   obj_typecode fieldName className1
        clazz = JavaClass()
        log_debug("[classdesc]", ident)
        ba = self._readString()
        clazz.name = ba
        log_debug("Class name: %s" % ba, ident)
        (serialVersionUID, newHandle, classDescFlags) = self._readStruct(">LLB")
        clazz.serialVersionUID = serialVersionUID
        clazz.flags = classDescFlags
        clazz.handle = newHandle

        self._add_reference(clazz, ident)

        log_debug("Serial: 0x%X newHandle: 0x%X. classDescFlags: 0x%X" % (serialVersionUID, newHandle, classDescFlags), ident)
        (length, ) = self._readStruct(">H")
        log_debug("Fields num: 0x%X" % length, ident)

        clazz.fields_names = []
        clazz.fields_types = []
        for fieldId in range(length):
            (typecode, ) = self._readStruct(">B")
            field_name = self._readString()
            field_type = None
            field_type = self._convert_char_to_type(typecode)

            if field_type == self.TYPE_ARRAY:
                opcode, field_type = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_STRING, self.TC_REFERENCE])
                assert type(field_type) is JavaString
#                if field_type is not None:
#                    field_type = "array of " + field_type
#                else:
#                    field_type = "array of None"
            elif field_type == self.TYPE_OBJECT:
                opcode, field_type = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_STRING, self.TC_REFERENCE])
                assert type(field_type) is JavaString

            log_debug("FieldName: 0x%X" % typecode + " " + str(field_name) + " " + str(field_type), ident)
            assert field_name is not None
            assert field_type is not None

            clazz.fields_names.append(field_name)
            clazz.fields_types.append(field_type)
        if parent:
            parent.__fields = clazz.fields_names
            parent.__types = clazz.fields_types
        # classAnnotation
        (opid, ) = self._readStruct(">B")
        log_debug("OpCode: 0x%X" % opid, ident)
        if opid != self.TC_ENDBLOCKDATA:
            raise NotImplementedError("classAnnotation isn't implemented yet")
        # superClassDesc
        opcode, superclassdesc = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_CLASSDESC, self.TC_NULL, self.TC_REFERENCE])
        log_debug(str(superclassdesc), ident)
        clazz.superclass = superclassdesc

        return clazz

    def do_blockdata(self, parent=None, ident=0):
        # TC_BLOCKDATA (unsigned byte)<size> (byte)[size]
        log_debug("[blockdata]", ident)
        (length, ) = self._readStruct(">B")
        ba = self.object_stream.read(length)
        return ba

    def do_blockdata_long(self, parent=None, ident=0):
        # TC_BLOCKDATALONG (int)<size> (byte)[size]
        log_debug("[blockdata]", ident)
        (length, ) = self._readStruct(">I")
        ba = self.object_stream.read(length)
        return ba

    def do_class(self, parent=None, ident=0):
        # TC_CLASS classDesc newHandle
        log_debug("[class]", ident)

        # TODO: what to do with "(ClassDesc)prevObject". (see 3rd line for classDesc:)
        opcode, classdesc = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_CLASSDESC, self.TC_PROXYCLASSDESC, self.TC_NULL, self.TC_REFERENCE])
        log_debug("Classdesc: %s" % classdesc, ident)
        self._add_reference(classdesc, ident)
        return classdesc

    def do_object(self, parent=None, ident=0):
        # TC_OBJECT classDesc newHandle classdata[]  // data for each class
        java_object = JavaObject()
        log_debug("[object]", ident)
        log_debug("java_object.annotations just after instantination: " + str(java_object.annotations), ident)

        # TODO: what to do with "(ClassDesc)prevObject". (see 3rd line for classDesc:)
        opcode, classdesc = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_CLASSDESC, self.TC_PROXYCLASSDESC, self.TC_NULL, self.TC_REFERENCE])
        # self.TC_REFERENCE hasn't shown in spec, but actually is here

        self._add_reference(java_object, ident)

        # classdata[]

        # Store classdesc of this object
        java_object.classdesc = classdesc

        if classdesc.flags & self.SC_EXTERNALIZABLE and not classdesc.flags & self.SC_BLOCK_DATA:
            raise NotImplementedError("externalContents isn't implemented yet") # TODO:

        if classdesc.flags & self.SC_SERIALIZABLE:
            # create megalist
            tempclass = classdesc
            megalist = []
            megatypes = []
            while tempclass:
                log_debug(">>> " + str(tempclass.fields_names) + " " + str(tempclass), ident)
                log_debug(">>> " + str(tempclass.fields_types), ident)
                fieldscopy = tempclass.fields_names[:]
                fieldscopy.extend(megalist)
                megalist = fieldscopy

                fieldscopy = tempclass.fields_types[:]
                fieldscopy.extend(megatypes)
                megatypes = fieldscopy

                tempclass = tempclass.superclass

            log_debug("Values count: %s" % str(len(megalist)), ident)
            log_debug("Prepared list of values: %s" % str(megalist), ident)
            log_debug("Prepared list of types: %s" % str(megatypes), ident)

            for field_name, field_type in zip(megalist, megatypes):
                res = self._read_value(field_type, ident, name=field_name)
                java_object.__setattr__(field_name, res)

        if classdesc.flags & self.SC_SERIALIZABLE and classdesc.flags & self.SC_WRITE_METHOD or classdesc.flags & self.SC_EXTERNALIZABLE and classdesc.flags & self.SC_BLOCK_DATA:
            # objectAnnotation
            log_debug("java_object.annotations before: " + str(java_object.annotations), ident)
            while opcode != self.TC_ENDBLOCKDATA:
                opcode, obj = self._read_and_exec_opcode(ident=ident+1) # , expect=[self.TC_ENDBLOCKDATA, self.TC_BLOCKDATA, self.TC_OBJECT, self.TC_NULL, self.TC_REFERENCE])
                if opcode != self.TC_ENDBLOCKDATA:
                    java_object.annotations.append(obj)
                log_debug("objectAnnotation value: " + str(obj), ident)
            log_debug("java_object.annotations after: " + str(java_object.annotations), ident)

        # Transform object
        for transformer in self.object_transformers:
            tmp_object = transformer.transform(java_object)
            if tmp_object is not java_object:
                java_object = tmp_object
                break

        log_debug(">>> java_object: " + str(java_object), ident)
        return java_object

    def do_string(self, parent=None, ident=0):
        log_debug("[string]", ident)
        ba = JavaString(self._readString())
        self._add_reference(ba, ident)
        return ba

    def do_string_long(self, parent=None, ident=0):
        log_debug("[long string]", ident)
        ba = JavaString(self._readString("Q"))
        self._add_reference(ba, ident)
        return ba

    def do_array(self, parent=None, ident=0):
        # TC_ARRAY classDesc newHandle (int)<size> values[size]
        log_debug("[array]", ident)
        opcode, classdesc = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_CLASSDESC, self.TC_PROXYCLASSDESC, self.TC_NULL, self.TC_REFERENCE])

        array = JavaArray(classdesc)

        self._add_reference(array, ident)

        (size, ) = self._readStruct(">i")
        log_debug("size: " + str(size), ident)

        type_char = classdesc.name[0]
        assert type_char == self.TYPE_ARRAY
        type_char = classdesc.name[1]

        if type_char == self.TYPE_OBJECT or type_char == self.TYPE_ARRAY:
            for i in range(size):
                opcode, res = self._read_and_exec_opcode(ident=ident+1)
                log_debug("Object value: %s" % str(res), ident)
                array.append(res)
        else:
            for i in range(size):
                res = self._read_value(type_char, ident)
                log_debug("Native value: %s" % str(res), ident)
                array.append(res)

        return array

    def do_reference(self, parent=None, ident=0):
        (handle, ) = self._readStruct(">L")
        log_debug("## Reference handle: 0x%x" % (handle), ident)
        return self.references[handle - self.BASE_REFERENCE_IDX]

    def do_null(self, parent=None, ident=0):
        return None

    def do_enum(self, parent=None, ident=0):
        # TC_ENUM classDesc newHandle enumConstantName
        enum = JavaEnum()
        opcode, classdesc = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_CLASSDESC, self.TC_PROXYCLASSDESC, self.TC_NULL, self.TC_REFERENCE])
        enum.classdesc = classdesc
        self._add_reference(enum, ident)
        opcode, enumConstantName = self._read_and_exec_opcode(ident=ident+1, expect=[self.TC_STRING, self.TC_REFERENCE])
        
        enum.constant = enumConstantName
        return enum

    def _create_hexdump(self, src, start_offset=0, length=16):
        FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        result = []
        for i in xrange(0, len(src), length):
            s = src[i:i+length]
            hexa = ' '.join(["%02X" % ord(x) for x in s])
            printable = s.translate(FILTER)
            result.append("%04X   %-*s  %s\n" % (i+start_offset, length*3, hexa, printable))
        return ''.join(result)

    def _read_value(self, field_type, ident, name = ""):
        if len(field_type) > 1:
            cls = field_type[1:]
            field_type = field_type[0]  # We don't need details for arrays and objects

        if field_type == self.TYPE_BOOLEAN:
            (val, ) = self._readStruct(">B")
            res = bool(val)
        elif field_type == self.TYPE_BYTE:
            (res, ) = self._readStruct(">b")
        elif field_type == self.TYPE_SHORT:
            (res, ) = self._readStruct(">h")
        elif field_type == self.TYPE_INTEGER:
            (res, ) = self._readStruct(">i")
        elif field_type == self.TYPE_LONG:
            (res, ) = self._readStruct(">q")
        elif field_type == self.TYPE_FLOAT:
            (res, ) = self._readStruct(">f")
        elif field_type == self.TYPE_DOUBLE:
            (res, ) = self._readStruct(">d")
        elif field_type == self.TYPE_OBJECT or field_type == self.TYPE_ARRAY:
            try:
                opcode, res = self._read_and_exec_opcode(ident=ident+1)
            except RuntimeError:
                if cls == 'java/lang/String;':
                    res = JavaString(self._readString())
                else:
                    raise
        else:
            raise RuntimeError("Unknown typecode: %s" % field_type)
        log_debug("* %s %s: " % (field_type, name) + str(res), ident)
        return res

    def _convert_char_to_type(self, type_char):
        typecode = type_char
        if type(type_char) is int:
            typecode = chr(type_char)

        if typecode in self.TYPECODES_LIST:
            return typecode
        else:
            raise RuntimeError("Typecode %s (%s) isn't supported." % (type_char, typecode))

    def _add_reference(self, obj, ident=0):
        log_debug('## New reference handle 0x%X' % (len(self.references) + self.BASE_REFERENCE_IDX,), ident)
        self.references.append(obj)

    def _oops_dump_state(self):
        log_error("==Oops state dump" + "=" * (30 - 17))
        log_error("References: %s" % str(self.references))
        log_error("Stream seeking back at -16 byte (2nd line is an actual position!):")
        self.object_stream.seek(-16, 1)
        position = self.object_stream.tell()
        the_rest = self.object_stream.read()
        if len(the_rest):
            log_error(self._create_hexdump(the_rest, position))
        log_error("=" * 30)


class JavaObjectMarshaller(JavaObjectConstants):

    def __init__(self, stream=None):
        self.object_stream = stream
        self.object_transformers = []

    def add_transformer(self, transformer):
        self.object_transformers.append(transformer)

    def dump(self, obj):

        self.object_obj = obj
        self.object_stream = io.StringIO()
        self._writeStreamHeader()
        self.writeObject(obj)
        return self.object_stream.getvalue()

    def _writeStreamHeader(self):
        self._writeStruct(">HH", 4, (self.STREAM_MAGIC, self.STREAM_VERSION))

    def writeObject(self, obj):
        log_debug("Writing object of type " + str(type(obj)) + " " + str(obj))
        if isinstance(obj, JavaArray):
            self.write_array(obj)
        elif isinstance(obj, JavaEnum):
            self.write_enum(obj)
        elif isinstance(obj, JavaObject):
            self.write_object(obj)
        elif isinstance(obj, JavaString):
            self.write_string(obj)
        elif isinstance(obj, JavaClass):
            self.write_class(obj)
        elif obj is None:
            self.write_null()
        elif type(obj) is str:
            self.write_blockdata(obj)
        else:
            raise RuntimeError("Object serialization of type %s is not supported." % str(type(obj)))

    def _writeStruct(self, unpack, length, args):
        ba = struct.pack(unpack, *args)
        self.object_stream.write(ba)

    def _writeString(self, string):
        length = len(string)
        self._writeStruct(">H", 2, (length, ))
        self.object_stream.write(string)

    def write_string(self, obj):
        self._writeStruct(">B", 1, (self.TC_STRING,))
        self._writeString(obj)

    def write_enum(self, obj):
        self._writeStruct(">B", 1, (self.TC_ENUM, ))
        self.write_classdesc(obj.get_class())

        self.write_string(obj.constant)

    def write_blockdata(self, obj, parent=None):
        # TC_BLOCKDATA (unsigned byte)<size> (byte)[size]
        length = len(obj)
        if length <= 256:
            self._writeStruct(">B", 1, (self.TC_BLOCKDATA, ))
            self._writeStruct(">B", 1, (length, ))
        else:
            self._writeStruct(">B", 1, (self.TC_BLOCKDATALONG, ))
            self._writeStruct(">I", 1, (length, ))
        self.object_stream.write(obj)

    def write_null(self):
        self._writeStruct(">B", 1, (self.TC_NULL, ))

    def write_object(self, obj, parent=None):
        
        # Transform object
        for transformer in self.object_transformers:
            tmp_object = transformer.transform(obj)
            if tmp_object is not obj:
                obj = tmp_object
                break

        self._writeStruct(">B", 1, (self.TC_OBJECT, ))
        cls = obj.get_class()
        self.write_classdesc(cls)

        all_names = []
        all_types = []
        tmpcls = cls
        while tmpcls:
            all_names += tmpcls.fields_names
            all_types += tmpcls.fields_types
            tmpcls = tmpcls.superclass

        del tmpcls
        for name, type in zip(all_names, all_types):
            try:
                self._write_value(type, getattr(obj, name))
            except AttributeError as e:
                log_error("%s e, %s %s" % (str(e), repr(obj), repr(dir(obj))))
                raise

        del all_names, all_types
        
        if (cls.flags & self.SC_SERIALIZABLE and cls.flags & self.SC_WRITE_METHOD or 
            cls.flags & self.SC_EXTERNALIZABLE and cls.flags & self.SC_BLOCK_DATA):
            for annot in obj.annotations:
                log_debug("Write annotation %s for %s" % (repr(annot), repr(obj),))
                if annot == None:
                    self.write_null()
                else:
                    self.writeObject(annot)
            self._writeStruct('>B', 1, (self.TC_ENDBLOCKDATA,))

    def write_class(self, obj, parent=None):
        self._writeStruct(">B", 1, (self.TC_CLASS,))
        self.write_classdesc(obj)

    def write_classdesc(self, obj, parent=None):
        self._writeStruct(">B", 1, (self.TC_CLASSDESC, ))
        self._writeString(obj.name)
        self._writeStruct(">LLB", 1, (obj.serialVersionUID, obj.handle, obj.flags))
        self._writeStruct(">H", 1, (len(obj.fields_names), ))
        
        for name,type in zip(obj.fields_names, obj.fields_types):
            self._writeStruct(">B", 1, 
                                (self._convert_type_to_char(type),))
            self._writeString(name)
            if type[0] in (self.TYPE_OBJECT, self.TYPE_ARRAY):
                self.write_string(type)

        self._writeStruct(">B", 1, (self.TC_ENDBLOCKDATA,))
        if obj.superclass:
            self.write_classdesc(obj.superclass)
        else:
            self.write_null()

    def write_array(self, obj):
        self._writeStruct(">B", 1, (self.TC_ARRAY,))
        self.write_classdesc(obj.get_class())
        self._writeStruct(">i", 1, (len(obj),))

        classdesc = obj.get_class()

        type_char = classdesc.name[0]
        assert type_char == self.TYPE_ARRAY
        type_char = classdesc.name[1]

        if type_char == self.TYPE_OBJECT:
            for o in obj:
                self.write_object(o)
        elif type_char == self.TYPE_ARRAY:
            for a in obj:
                self.write_array(a)
        else:
            log_debug("Write array of type %s" % type_char)
            for v in obj:
                self._write_value(type_char, v)
    
    def _write_value(self, field_type, value):
        if len(field_type) > 1:
            field_type = field_type[0]  # We don't need details for arrays and objects

        if field_type == self.TYPE_BOOLEAN:
            self._writeStruct(">B", 1, (1 if value else 0,))
        elif field_type == self.TYPE_BYTE:
            if value > 127:
                self._writeStruct(">B", 1, (value,))
            else:
                self._writeStruct(">b", 1, (value,))
        elif field_type == self.TYPE_SHORT:
            self._writeStruct(">h", 1, (value,))
        elif field_type == self.TYPE_INTEGER:
            self._writeStruct(">i", 1, (value,))
        elif field_type == self.TYPE_LONG:
            self._writeStruct(">q", 1, (value,))
        elif field_type == self.TYPE_FLOAT:
            self._writeStruct(">f", 1, (value,))
        elif field_type == self.TYPE_DOUBLE:
            self._writeStruct(">d", 1, (value,))
        elif field_type == self.TYPE_OBJECT or field_type == self.TYPE_ARRAY:
            if value == None:
                self.write_null()
            elif isinstance(value, JavaEnum):
                self.write_enum(value)
            elif isinstance(value, JavaObject):
                self.write_object(value)
            elif isinstance(value, JavaString):
                self.write_string(value)
            elif isinstance(value, str):
                self.write_blockdata(value)
            else:
                raise RuntimeError("Unknown typecode: %s" % field_type)
        else:
            raise RuntimeError("Unknown typecode: %s" % field_type)
 
    def _convert_type_to_char(self, type_char):
        typecode = type_char
        if type(type_char) is int:
            typecode = chr(type_char)

        if typecode in self.TYPECODES_LIST:
            return ord(typecode)
        elif len(typecode) > 1:
            if typecode[0] == 'L':
                return ord(self.TYPE_OBJECT)
            elif typecode[0] == '[':
                return ord(self.TYPE_ARRAY)

        raise RuntimeError("Typecode %s (%s) isn't supported." % (type_char, typecode))

class DefaultObjectTransformer(object):

    class JavaList(list, JavaObject):
        def __init__(self, *args, **kwargs):
            list.__init__(self, *args, **kwargs)
            JavaObject.__init__(self)

    class JavaMap(dict, JavaObject):
        def __init__(self, *args, **kwargs):
            dict.__init__(self, *args, **kwargs)
            JavaObject.__init__(self)

    def transform(self, object):
        if object.get_class().name == "java.util.ArrayList":
            #    * @serialData The length of the array backing the <tt>ArrayList</tt>
            #    *             instance is emitted (int), followed by all of its elements
            #    *             (each an <tt>Object</tt>) in the proper order.
            #print "---"
            #print "java.util.ArrayList"
            #print object.annotations
            #print "---"
            new_object = self.JavaList()
            object.copy(new_object)
            new_object.extend(object.annotations[1:])
            #print ">>> object:", new_object
            return new_object
        if object.get_class().name == "java.util.LinkedList":
            #print "---"
            #print
            #print "java.util.LinkedList"
            #print object.annotations
            #print "---"
            new_object = self.JavaList()
            object.copy(new_object)
            new_object.extend(object.annotations[1:])
            #print ">>> object:", new_object
            return new_object
        if object.get_class().name == "java.util.HashMap":
            #print "---"
            #print
            #print "java.util.HashMap"
            #print object.annotations
            #print "---"
            new_object = self.JavaMap()
            object.copy(new_object)

            for i in range(1, len(object.annotations),2):
                new_object[object.annotations[i]] = object.annotations[i+1]

            #print ">>> object:", new_object
            return new_object

        return object
