public class VulnerableSalesforceApp {
    // Vulnerabilidad 1: Inyección de SOQL sin sanitización
    public List<Contact> searchContactsUnsafely(String searchTerm) {
        // Riesgo de SOQL Injection
        String query = 'SELECT Id, Name, Email FROM Contact WHERE Name LIKE \'%' + searchTerm + '%\'';
        return Database.query(query);
    }

    // Vulnerabilidad 2: Exposición de Datos Sensibles
    public class UserCredentials {
        public String username;
        public String password; // Nunca almacenar contraseñas en texto plano
        
        // Método que expone información sensible
        public String getFullCredentials() {
            return username + ':' + password;
        }
    }

    // Vulnerabilidad 3: Validación Insuficiente de Entrada
    public void processExternalData(String userInput) {
        // Sin validación de entrada
        System.debug('Procesando: ' + userInput);
        
        // Posible reflected XSS en debug log
        Account newAccount = new Account();
        newAccount.Name = userInput;
        insert newAccount;
    }

    // Vulnerabilidad 4: Falta de Controles de Acceso
    @AuraEnabled
    public static List<Opportunity> getAllOpportunities() {
        // Método que permite acceso sin verificación de permisos
        return [SELECT Id, Name, Amount FROM Opportunity];
    }

    // Vulnerabilidad 5: Deserialización Insegura
    public class UnsafeDeserializationExample {
        // Método que podría permitir ejecución de código malicioso
        public static Object deserializeData(String serializedData) {
            try {
                // En Apex, esto podría ser un riesgo si se usa con datos no confiables
                return JSON.deserialize(serializedData, Schema.Account.class);
            } catch (Exception e) {
                System.debug('Error en deserialización: ' + e.getMessage());
                return null;
            }
        }
    }

    // Método adicional demostrando múltiples vulnerabilidades
    public void vulnerableMethod(String userProvidedInput) {
        // Ejemplo combinado de múltiples riesgos
        try {
            // Posible SOQL Injection
            List<Contact> contacts = Database.query('SELECT Id, Name FROM Contact WHERE Name = \'' + userProvidedInput + '\'');
            
            // Posible XSS en diferentes contextos
            System.debug('Entrada del usuario: ' + userProvidedInput);
            
            // Creación de registro sin sanitización
            Contact newContact = new Contact();
            newContact.LastName = userProvidedInput;
            insert newContact;
        } catch (Exception e) {
            // Logging inseguro que podría exponer detalles internos
            System.debug('Error completo: ' + e.getMessage() + '\n' + e.getStackTraceString());
        }
    }

    // Ejemplo de método con mitigación (para comparación)
    public List<Contact> searchContactsSafely(String searchTerm) {
        // Uso de parámetros de enlace para prevenir SOQL Injection
        String safeTerm = String.escapeSingleQuotes(searchTerm);
        return [SELECT Id, Name, Email 
                FROM Contact 
                WHERE Name LIKE :('%' + safeTerm + '%')];
    }
}

// Clase adicional para demostrar vulnerabilidades de Visualforce/Lightning
public with sharing class VulnerableVFController {
    // Vulnerabilidad de XSS en Visualforce
    public String userInput { get; set; }
    
    public PageReference processInput() {
        // Sin sanitización, vulnerable a XSS
        ApexPages.addMessage(new ApexPages.Message(
            ApexPages.Severity.INFO, 
            'Entrada del usuario: ' + userInput
        ));
        return null;
    }
}
