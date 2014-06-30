'''
Created on May 17, 2014

@author: rpiazza
'''

from datetime import datetime, timedelta
import json
import os
import sys

import dateutil
from xml.sax.saxutils import escape
from stix.coa import (CourseOfAction)
from stix.common import (Statement, Confidence, InformationSource, RelatedThreatActor, DateTimeWithPrecision, Identity)
from stix.common.related import (RelatedTTP, RelatedExploitTarget)
from stix.common.vocabs import (VocabString, Motivation, ThreatActorType, MalwareType, LossProperty, AvailabilityLossType,
                                DiscoveryMethod, HighMediumLow, AssetType, ManagementClass, OwnershipClass, SecurityCompromise,
                                ImpactRating, LossDuration)
from stix.core import STIXPackage, STIXHeader
from stix.exploit_target import (ExploitTarget, Vulnerability)
from stix.extensions.identity.ciq_identity_3_0 import (CIQIdentity3_0Instance, STIXCIQIdentity3_0, Country,
                                                       Address, OrganisationInfo, PartyName)
from stix.incident import (Incident, AffectedAsset, PropertyAffected, Time, LeveragedTTPs, ExternalID)
from stix.incident.impact_assessment import (ImpactAssessment, TotalLossEstimation, ImpactQualification)
from stix.incident.direct_impact_summary import DirectImpactSummary
from stix.incident.loss_estimation import LossEstimation
from stix.threat_actor import (ThreatActor, ObservedTTPs)
from stix.ttp import (TTP, Behavior, VictimTargeting, ExploitTargets)
from stix.ttp.attack_pattern import (AttackPattern)
from stix.ttp.malware_instance import (MalwareInstance)
from stix.ttp.exploit import (Exploit)

def findFile(inFileName):
    physicalPresent = False
    multipleAssets = False
    with open(inFileName) as json_data:
        veris_item = json.load(json_data)
        json_data.close()

    #action_item = veris_item.get('action')
    #if action_item != None:
    #    if action_item.get('physical'):
    #        physicalPresent = True
        
    actors = 0
    actor_item = veris_item.get('actor')
    if actor_item != None:
        if actor_item.get('internal'):
            actors += 1
        if actor_item.get('external'):
            actors += 1
        if actor_item.get('partner'):
            actors += 1           
        if actor_item.get('unknown'):
            actors += 1
    #asset_item = veris_item.get('asset')
    #if asset_item != None:
    #    assets_item = asset_item.get('assets')
    #    if len(assets_item) > 1:
    #        multipleAssets = True

    #confidence_item = veris_item.get('confidence')

    #control_failure - not found in data

    #corrective_action_item = veris_item.get('corrective_action')
    #cost_corrective_action_item = veris_item.get('cost_corrective_action')
    
    #discovery_method_item = veris_item.get('discovery_method')
    #if discovery_method_item == None:
        
 
    #impact_item = veris_item.get('impact')    
    #if impact_item != None:
        
    #incident_id_item = veris_item.get('incident_id') 
    #if incident_id_item == None:
        
    #notes_item = veris_item.get('notes')      
    #if notes_item != None:
        
    #plus_item = veris_item.get('plus')
    #if plus_item != None:
    #    if plus_item.get('asset'):
    #        return True
        
    #if veris_item.get('related_incidents') != None:
        
    # schema_version
    #security_incident_item = veris_item.get('security_incident')
    #if security_incident_item == None:
        
    #reference_item = veris_item.get('reference')
    #source_id_item = veris_item.get('source_id')
    #if source_id_item != None or reference_item != None:
        
    #summary_item = veris_item.get('summary')
    #if summary_item != None:   
    
    #timeline_item = veris_item.get('timeline')
    #if timeline_item == None:
    
    #victim_item = veris_item.get('victim')
    return actors > 1
    
def find(inDir):
    for fName in os.listdir(inDir):
        fNameParts = fName.split('.')
        if fNameParts[1] != "json":
            sys.stderr.write("Skipping " + fName + " - not a json file")
        else:
            if findFile(inDir + "\\" + fName):
                print fName
        
if __name__ == '__main__':
    find(sys.argv[1])