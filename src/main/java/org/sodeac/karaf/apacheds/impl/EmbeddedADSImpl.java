/*
 *  Copyright (c) 2019 Sebastian Palarus
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package org.sodeac.karaf.apacheds.impl;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeTypeOptions;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.CsnSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.GeneralizedTimeSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.UuidSyntaxChecker;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.DateUtils;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.config.ConfigPartitionInitializer;
import org.apache.directory.server.config.ConfigPartitionReader;
import org.apache.directory.server.config.beans.ConfigBean;
import org.apache.directory.server.config.beans.DirectoryServiceBean;
import org.apache.directory.server.config.beans.TransportBean;
import org.apache.directory.server.config.builder.ServiceBuilder;
import org.apache.directory.server.config.listener.ConfigChangeListener;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.event.EventType;
import org.apache.directory.server.core.api.event.NotificationCriteria;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.integration.http.HttpServer;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ntp.NtpServer;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.log.LogService;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.sodeac.karaf.apacheds.api.IEmbeddedADS;

// based on https://github.com/apache/directory-server/blob/master/service/src/main/java/org/apache/directory/server/ApacheDsService.java
@Component
(
	immediate=true,
	configurationPid	= EmbeddedADSImpl.SERVICE_PID	, 
	configurationPolicy	= ConfigurationPolicy.REQUIRE,
	service=IEmbeddedADS.class
)
public class EmbeddedADSImpl implements IEmbeddedADS
{
	@Reference
	protected volatile LogService logService;
	
	protected ComponentContext context = null;
	protected Map<String, ?> properties = null;
	
	private SchemaManager schemaManager = null;
	private LdifPartition schemaLdifPartition = null;
	private LdifPartition configPartition = null;
	private ConfigPartitionReader cpReader = null;
	private CacheService cacheService = null;
	private DirectoryService directoryService = null;
	private LdapServer ldapServer = null;
	private NtpServer ntpServer = null;
	private KdcServer kdcServer = null;
	private HttpServer httpServer = null;
	private InstanceLayout instanceLayout = null;
	
	private static final Map<String, AttributeTypeOptions> MANDATORY_ENTRY_ATOP_MAP = new HashMap<String, AttributeTypeOptions>();
    private static final String[] MANDATORY_ENTRY_ATOP_AT = new String[5];
    
    // variables used during the initial startup to update the mandatory operational
    // attributes
    /** The UUID syntax checker instance */
    private UuidSyntaxChecker uuidChecker = UuidSyntaxChecker.INSTANCE;

    /** The CSN syntax checker instance */
    private CsnSyntaxChecker csnChecker = CsnSyntaxChecker.INSTANCE;

    private GeneralizedTimeSyntaxChecker timeChecker = GeneralizedTimeSyntaxChecker.INSTANCE;
	
	public static final String SERVICE_PID = "org.sodeac.karaf.apacheds";
	
	@ObjectClassDefinition(name=SERVICE_PID, description="Configuration of Apachy DS Instance",factoryPid=EmbeddedADSImpl.SERVICE_PID)
	interface Config
	{
		@AttributeDefinition(name="servicename", description = "name of directory service" , type=AttributeType.STRING, required=false)
		String servicename();
		
		@AttributeDefinition(name="directory",description = "file backend of directory service" ,type=AttributeType.STRING, required=true)
		String directory();
		
		@AttributeDefinition(name="ldapaddress",description = "ldap network address of directory service (overwrite ou=config)" ,type=AttributeType.STRING, required=false)
		String ldapaddress();
		
		@AttributeDefinition(name="ldapport",description = "ldap port of directory service (overwrite ou=config)" ,type=AttributeType.INTEGER,  required=false)
		int ldapport();
		
		@AttributeDefinition(name="ldapsaddress",description = "ldaps network address of directory service (overwrite ou=config)" ,type=AttributeType.STRING, required=false)
		String ldapsaddress();
		
		@AttributeDefinition(name="ldapsport",description = "ldaps port of directory service (overwrite ou=config)" ,type=AttributeType.INTEGER,  required=false)
		int ldapsport();
		
		@AttributeDefinition(name="allowanonymousaccess",description = "allow anonymous access (overwrite ou=config)" ,type=AttributeType.BOOLEAN,  required=false)
		boolean allowanonymousaccess();
	}
	
	@Activate
	public void activate(ComponentContext context, Map<String, ?> properties) throws Exception
	{
		this.context = context;
		this.properties = properties;
		
		this.start();
	}
	
	@Override
	public void start() throws Exception
	{
		try
		{
			String serviceName = (String)properties.get("servicename");
			if((serviceName == null) || (serviceName.isEmpty()))
			{
				serviceName = "default";
			}
			
			String ldapAddress = (String)properties.get("ldapaddress");
			Integer ldapPort = null;
			if(properties.get("ldapport") != null)
			{
				if(properties.get("ldapport") instanceof Integer)
				{
					ldapPort = (Integer)properties.get("ldapport");
				}
				else if(properties.get("ldapport") instanceof String)
				{
					if(! ((String)properties.get("ldapport")).isEmpty())
					{
						ldapPort = Integer.parseInt((String)properties.get("ldapport"));
					}
				}
			}
			
			String ldapsAddress = (String)properties.get("ldapsaddress");
			Integer ldapsPort = null;
			if(properties.get("ldapsport") != null)
			{
				if(properties.get("ldapsport") instanceof Integer)
				{
					ldapsPort = (Integer)properties.get("ldapsport");
				}
				else if(properties.get("ldapsport") instanceof String)
				{
					if(! ((String)properties.get("ldapsport")).isEmpty())
					{
						ldapsPort = Integer.parseInt((String)properties.get("ldapsport"));
					}
				}
			}
			
			Boolean allowAnonymousAccess = null;
			if(properties.get("allowanonymousaccess") != null)
			{
				if(properties.get("allowanonymousaccess") instanceof Boolean)
				{
					allowAnonymousAccess = (Boolean)properties.get("allowanonymousaccess");
				}
				else if(properties.get("allowanonymousaccess") instanceof String)
				{
					if(! ((String)properties.get("allowanonymousaccess")).isEmpty())
					{
						allowAnonymousAccess = Boolean.parseBoolean((String)properties.get("allowanonymousaccess"));
					}
				}
			}
			
			String directory = (String)properties.get("directory");
			
			this.instanceLayout = new InstanceLayout( new File(directory));
			File partitionsDir = instanceLayout.getPartitionsDirectory();

			if ( !partitionsDir.exists() )
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "partition directory doesn't exist, creating " + partitionsDir.getAbsolutePath() );
				
				if ( !partitionsDir.mkdirs() )
				{
					throw new IOException( I18n.err( I18n.ERR_112_COULD_NOT_CREATE_DIRECTORY, partitionsDir ) );
				}
			}
			
			CacheService cacheService = new CacheService();
			cacheService.initialize( instanceLayout );
			
			// Initialize the schema Manager by loading the schema LDIF files
			
			File schemaPartitionDirectory = new File( instanceLayout.getPartitionsDirectory(), "schema" );
			
			boolean isSchemaPartitionFirstExtraction = false;
			
			// Extract the schema on disk (a brand new one) and load the registries
			if (! schemaPartitionDirectory.exists() )
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "schema partition not exists, extract schema" );
				SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( instanceLayout.getPartitionsDirectory() );
				extractor.extractOrCopy();
				isSchemaPartitionFirstExtraction = true;
			}
			
			SchemaLoader loader = new LdifSchemaLoader( schemaPartitionDirectory );
			schemaManager = new DefaultSchemaManager( loader.getAllSchemas() );
			
			// We have to load the schema now, otherwise we won't be able
			// to initialize the Partitions, as we won't be able to parse
			// and normalize their suffix Dn
			schemaManager.loadAllEnabled();
			
			List<Throwable> errors = schemaManager.getErrors();
			
			if ( errors.size() != 0 )
			{
				throw new Exception( I18n.err( I18n.ERR_317, Exceptions.printErrors( errors ) ) );
			}
			
			// dnCache
			
			DnFactory dnFactory = new DefaultDnFactory( schemaManager, cacheService.getCache( "dnCache" ) );
			
			// Initialize the schema partition
			
			schemaLdifPartition = new LdifPartition( schemaManager, dnFactory );
			schemaLdifPartition.setPartitionPath( schemaPartitionDirectory.toURI() );
			
			// initializes a LDIF partition for configuration
			
			ConfigPartitionInitializer initializer = new ConfigPartitionInitializer( instanceLayout, dnFactory, cacheService, schemaManager );
			configPartition = initializer.initConfigPartition();
			
			// Read the configuration
			cpReader = new ConfigPartitionReader( configPartition );
			
			ConfigBean configBean = cpReader.readConfig();
			
			DirectoryServiceBean directoryServiceBean = configBean.getDirectoryServiceBean();
			directoryServiceBean.setDirectoryServiceId(serviceName);
			
			if(allowAnonymousAccess != null)
			{
				directoryServiceBean.setDsAllowAnonymousAccess(allowAnonymousAccess.booleanValue());
			}
			
			logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Initializing the DirectoryService..." );
			
			long startTime = System.currentTimeMillis();
			
			directoryService = ServiceBuilder.createDirectoryService( directoryServiceBean,instanceLayout, schemaManager );
			
			// Inject the DnFactory
			directoryService.setDnFactory( dnFactory );
			
			// The schema partition
			SchemaPartition schemaPartition = new SchemaPartition( schemaManager );
			schemaPartition.setWrappedPartition( schemaLdifPartition );
			directoryService.setSchemaPartition( schemaPartition );
			
			directoryService.addPartition( configPartition );
			
			// Store the default directories
			directoryService.setInstanceLayout( instanceLayout );
			
			directoryService.setCacheService( cacheService );
			
			directoryService.setShutdownHookEnabled(false);
			directoryService.setExitVmOnShutdown(false);
			
			// start ads
			
			directoryService.startup();
			
			org.apache.directory.api.ldap.model.schema.AttributeType ocAt = directoryService.getAtProvider().getObjectClass();
			MANDATORY_ENTRY_ATOP_MAP.put( ocAt.getName(), new AttributeTypeOptions( ocAt ) );
			
			org.apache.directory.api.ldap.model.schema.AttributeType uuidAt = directoryService.getAtProvider().getEntryUUID();
			MANDATORY_ENTRY_ATOP_MAP.put( uuidAt.getName(), new AttributeTypeOptions( uuidAt ) );
			
			org.apache.directory.api.ldap.model.schema.AttributeType csnAt = directoryService.getAtProvider().getEntryCSN();
			MANDATORY_ENTRY_ATOP_MAP.put( csnAt.getName(), new AttributeTypeOptions( csnAt ) );
			
			org.apache.directory.api.ldap.model.schema.AttributeType creatorAt = directoryService.getAtProvider().getCreatorsName();
			MANDATORY_ENTRY_ATOP_MAP.put( creatorAt.getName(), new AttributeTypeOptions( creatorAt ) );
			
			org.apache.directory.api.ldap.model.schema.AttributeType createdTimeAt = directoryService.getAtProvider().getCreateTimestamp();
			MANDATORY_ENTRY_ATOP_MAP.put( createdTimeAt.getName(), new AttributeTypeOptions( createdTimeAt ) );
			
			int pos = 0;
			
			for ( AttributeTypeOptions attributeTypeOptions : MANDATORY_ENTRY_ATOP_MAP.values() )
			{
				MANDATORY_ENTRY_ATOP_AT[pos++] = attributeTypeOptions.getAttributeType().getName();
			}
			
			if ( isSchemaPartitionFirstExtraction )
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "begining to update schema partition LDIF files after modifying manadatory attributes" );
				
				updateMandatoryOpAttributes( schemaLdifPartition, directoryService );
				
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "schema partition data was successfully updated" );
			}
			
			logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "DirectoryService initialized in {} milliseconds" + ( System.currentTimeMillis() - startTime ) );
			
			// LDAP Server
			
			logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Starting the LDAP server" );
			startTime = System.currentTimeMillis();
			
			if((directoryServiceBean.getLdapServerBean() != null) && directoryServiceBean.getLdapServerBean().isEnabled())
			{
				for(TransportBean transport : directoryServiceBean.getLdapServerBean().getTransports())
				{
					if("ldap".equals(transport.getTransportId()))
					{
						if("-".equals(ldapAddress))
						{
							transport.setEnabled(false);
							continue;
						}
						
						if((ldapAddress != null) && (!ldapAddress.isEmpty()) && (!ldapAddress.equals(transport.getTransportAddress())))
						{
							transport.setEnabled(true);
							transport.setTransportAddress(ldapAddress);
						}
						
						if((ldapPort != null) && (ldapPort.intValue() != transport.getSystemPort()))
						{
							if(ldapPort < 1)
							{
								transport.setEnabled(false);
							}
							else
							{
								transport.setSystemPort(ldapPort);
							}
						}
					}
					
					if("ldaps".equals(transport.getTransportId()))
					{
						if("-".equals(ldapsAddress))
						{
							transport.setEnabled(false);
							continue;
						}
						
						if((ldapsAddress != null) && (!ldapsAddress.isEmpty()) && (!ldapsAddress.equals(transport.getTransportAddress())))
						{
							transport.setEnabled(true);
							transport.setTransportAddress(ldapsAddress);
						}
						
						if((ldapsPort != null) && (ldapsPort != transport.getSystemPort()))
						{
							if(ldapsPort < 1)
							{
								transport.setEnabled(false);
							}
							else
							{
								transport.setSystemPort(ldapsPort);
							}
						}
					}
				}
				
				startTime = System.currentTimeMillis();
				ldapServer = ServiceBuilder.createLdapServer( directoryServiceBean.getLdapServerBean(), directoryService );
				
				if ( ldapServer == null )
				{
					if((directoryServiceBean.getLdapServerBean() != null) && directoryServiceBean.getLdapServerBean().isEnabled())
					{
						logService.log(this.context.getServiceReference(),LogService.LOG_ERROR, "Cannot find any reference to the LDAP Server in the configuration : the server won't be started" );
					}
				}
				else
				{
					ldapServer.start();
					
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "LDAP server: started in " + ( System.currentTimeMillis() - startTime ) + " milliseconds");
				}
			}
			
			if((directoryServiceBean.getNtpServerBean() != null) && (directoryServiceBean.getNtpServerBean().isEnabled()))
			{
				
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Creating NTP server" );
				
				startTime = System.currentTimeMillis();
				ntpServer = ServiceBuilder.createNtpServer( directoryServiceBean.getNtpServerBean(), directoryService );
				
				if ( ntpServer == null )
				{
					logService.log(this.context.getServiceReference(),LogService.LOG_ERROR,  "Cannot find any reference to the NTP Server in the configuration : the server won't be started" );
				}
				else
				{
					ntpServer.start();
					
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG,  "NTP server: started in "+ ( System.currentTimeMillis() - startTime ) + " milliseconds" );
				}
			}
			
			if((directoryServiceBean.getKdcServerBean() != null) && directoryServiceBean.getKdcServerBean().isEnabled())
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Creating Kerberos server" );
				
				startTime = System.currentTimeMillis();
				
				kdcServer = ServiceBuilder.createKdcServer( directoryServiceBean, directoryService );
				if ( kdcServer == null )
				{
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Cannot find any reference to the Kerberos Server in the configuration : the server won't be started" );
				}
				else
				{
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG,  "Starting the Kerberos server" );
					
					ldapServer.getDirectoryService().startup();
					kdcServer.setDirectoryService( ldapServer.getDirectoryService() );
					
					kdcServer.start();
					
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Kerberos server: started in " + ( System.currentTimeMillis() - startTime ) + " milliseconds");
				}
			}
			
			
			if((directoryServiceBean.getHttpServerBean() != null) && directoryServiceBean.getHttpServerBean().isEnabled())
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Creating HTTP server" );
				
				startTime = System.currentTimeMillis();
				
				httpServer = ServiceBuilder.createHttpServer( directoryServiceBean.getHttpServerBean(), directoryService );
				
				if ( httpServer == null )
				{
					logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "Cannot find any reference to the HTTP Server in the configuration : the server won't be started" );
				}
				
				httpServer.start( ldapServer.getDirectoryService() );
				
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "HTTP server: started in " + ( System.currentTimeMillis() - startTime ) + " milliseconds");
			}
			
			
			logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG,  "Registering config change listener" );
			ConfigChangeListener configListener = new ConfigChangeListener( cpReader, directoryService );
			
			NotificationCriteria criteria = new NotificationCriteria( directoryService.getSchemaManager() );
			criteria.setBase( configPartition.getSuffixDn() );
			criteria.setEventMask( EventType.ALL_EVENT_TYPES_MASK );
			
			PresenceNode filter = new PresenceNode( SchemaConstants.OBJECT_CLASS_AT );
			criteria.setFilter( filter );
			criteria.setScope( SearchScope.SUBTREE );
			
			directoryService.getEventService().addListener( configListener, criteria );
		}
		catch (Exception ex) 
		{
			this.stop();
			throw ex;
		}
	}
	
	@Deactivate
	public void deactivate(ComponentContext context) throws Exception 
	{
		this.stop();
		this.properties = null;
		this.context = null;
	}
	
	@Override
	public void stop() 
	{
		try
		{
			if(this.httpServer != null)
			{
				this.httpServer.stop();
				this.httpServer = null;
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error stop http  service",e);
		}
		
		try
		{
			if(this.kdcServer != null)
			{
				this.kdcServer.stop();
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error stop kdc  service",e);
		}
		
		try
		{
			if(this.ntpServer != null)
			{
				this.ntpServer.stop();
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error stop ntp service",e);
		}
		
		try
		{
			if(this.ldapServer != null)
			{
				this.ldapServer.stop();
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error stop ldap service",e);
		}
		
		try
		{
			if(this.directoryService != null)
			{
				this.directoryService.shutdown();
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error stop directory service",e);
		}
		
		try
		{
			if(this.cacheService != null)
			{
				this.cacheService.destroy();
			}
		}
		catch (Exception e) 
		{
			logService.log(context.getServiceReference(),LogService.LOG_ERROR, "error destroy cache service",e);
		}
		
		this.instanceLayout = null;
	}
	
	@Modified 
	public void modified(Map<String, ?> properties) throws Exception
	{
		this.properties = properties;
		this.stop();
		this.start();
	}
	
	@Override
	public void synch() throws Exception
	{
		ldapServer.getDirectoryService().sync();
	}
	
	@Override
	public void repair() throws Exception
	{
		InstanceLayout instanceLayout = this.instanceLayout;
		if(instanceLayout == null)
		{
			String directory = (String)properties.get("directory");
			instanceLayout = new InstanceLayout( new File(directory));
		}
		
		File partitionsDir = this.instanceLayout.getPartitionsDirectory();
		
		logService.log(context.getServiceReference(), LogService.LOG_INFO, "Repairing partition dir " + partitionsDir.getAbsolutePath() );
		Set<? extends Partition> partitions = this.ldapServer.getDirectoryService().getPartitions();
		
		// Iterate on the partitions to repair them
		for ( Partition partition : partitions )
		{
			try
			{
				partition.repair();
			}
			catch ( Exception e )
			{
				logService.log(context.getServiceReference(),LogService.LOG_ERROR, "Failed to repair the partition " + partition.getId(),e);
			}
		}
	}
	
	public void updateMandatoryOpAttributes( Partition partition, DirectoryService dirService ) throws Exception
	{
		CoreSession session = dirService.getAdminSession();
		String adminDn = session.getEffectivePrincipal().getName();
		ExprNode filter = new PresenceNode( SchemaConstants.OBJECT_CLASS_AT );
		
		Cursor<Entry> cursor = session.search( partition.getSuffixDn(), SearchScope.SUBTREE, filter,AliasDerefMode.NEVER_DEREF_ALIASES, MANDATORY_ENTRY_ATOP_AT );
		cursor.beforeFirst();
		
		List<Modification> mods = new ArrayList<Modification>();
		
		while ( cursor.next() )
		{
			Entry entry = cursor.get();
			org.apache.directory.api.ldap.model.schema.AttributeType atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.ENTRY_UUID_AT ).getAttributeType();
			
			Attribute uuidAt = entry.get( atType );
			String uuid = ( uuidAt == null ? null : uuidAt.getString() );
			if ( !uuidChecker.isValidSyntax( uuid ) )
			{
				uuidAt = new DefaultAttribute( atType, UUID.randomUUID().toString() );
			}
			
			Modification uuidMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, uuidAt );
			mods.add( uuidMod );
			
			atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.ENTRY_CSN_AT ).getAttributeType();
			Attribute csnAt = entry.get( atType );
			String csn = ( csnAt == null ? null : csnAt.getString() );
			
			if ( !csnChecker.isValidSyntax( csn ) )
			{
				csnAt = new DefaultAttribute( atType, dirService.getCSN().toString() );
			}
			
			Modification csnMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, csnAt );
			mods.add( csnMod );
			
			atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.CREATORS_NAME_AT ).getAttributeType();
			Attribute creatorAt = entry.get( atType );
			String creator = ( creatorAt == null ? "" : creatorAt.getString().trim() );
			
			if ( ( creator.length() == 0 ) || ( !Dn.isValid( creator ) ) )
			{
				creatorAt = new DefaultAttribute( atType, adminDn );
			}
			
			Modification creatorMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, creatorAt );
			mods.add( creatorMod );
			
			atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.CREATE_TIMESTAMP_AT ).getAttributeType();
			Attribute createdTimeAt = entry.get( atType );
			String createdTime = ( createdTimeAt == null ? null : createdTimeAt.getString() );
			
			if ( !timeChecker.isValidSyntax( createdTime ) )
			{
				createdTimeAt = new DefaultAttribute( atType, DateUtils.getGeneralizedTime() );
			}
			
			Modification createdMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, createdTimeAt );
			mods.add( createdMod );
			
			if ( !mods.isEmpty() )
			{
				logService.log(this.context.getServiceReference(),LogService.LOG_DEBUG, "modifying the entry " + entry.getDn() + " after adding missing manadatory operational attributes" );
				ModifyOperationContext modifyContext = new ModifyOperationContext( session );
				modifyContext.setEntry( entry );
				modifyContext.setDn( entry.getDn() );
				modifyContext.setModItems( mods );
				partition.modify( modifyContext );
			}
			
			mods.clear();
		}
		
		cursor.close();
	}
}
