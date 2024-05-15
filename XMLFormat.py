
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

import xml.etree.ElementTree as ET
import xml.dom.minidom
from layers.V2G import *
from EXIProcessor import EXIProcessor
from EmulatorEnum import *



class PacketHandler:
    def __init__(self):
        # 초기화 코드 추가
        pass
    
    def SupportedAppProtocolRequest(self):
        self._cleanup()
        self.root = ET.Element("ns4:supportedAppProtocolReq")
        self.root.set("xmlns:ns4", "urn:iso:15118:2:2010:AppProtocol")
        self.root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        self.root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
        self.AppProtocol = ET.SubElement(self.root, "AppProtocol")
        self.ProtocolNamespace = ET.SubElement(self.AppProtocol, "ProtocolNamespace")
        self.VersionNumberMajor = ET.SubElement(self.AppProtocol, "VersionNumberMajor")
        self.VersionNumberMinor = ET.SubElement(self.AppProtocol, "VersionNumberMinor")
        self.SchemaID = ET.SubElement(self.AppProtocol, "SchemaID")
        self.Priority = ET.SubElement(self.AppProtocol, "Priority")

        # Default Values
        self.ProtocolNamespace.text = "urn:din:70121:2012:MsgDef"
        # self.ProtocolNamespace.text = "urn:iso:15118:2:2013:MsgDef"
        self.VersionNumberMajor.text = "2"
        self.VersionNumberMinor.text = "0"
        self.SchemaID.text = "1"
        self.Priority.text = "1"
        
    def _cleanup(self):
        # 정리 작업을 수행하는 메서드 추가
        pass