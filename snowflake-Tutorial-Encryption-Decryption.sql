/*
    Generate the Keys in the Snowflake for the encryption and decryption
*/
select 
   sha2('myScret', 256) as encryption_key
  ,substr(to_binary(hex_encode('everyThingMoreThan86'), 'hex'), 0, 12) as initialization_vector
  ,to_binary(hex_encode('additional_authenticated_data')) as aad_;
  
 
 
/*
    Encrypting and masking your data 
    Here we are using two techniques, encryption and encoding, so do you get the most powerful security (encrypt_raw, hex_encode
*/
select 
 encrypt_raw(
    to_binary(hex_encode('Hellow world'), 'HEX') -- data target
   ,to_binary('88327c5fe63fb2439c17e733e6aa2437bdb8aa24904f32775dfac12996db7cee') -- encryption_key
   ,to_binary('65766572795468696E674D6F') -- initialization_vector
   ,to_binary('6164646974696F6E616C5F61757468656E746963617465645F64617461') -- aad_column
   ,'AES-GCM'
 ) as col_encrypted;


--creating the temporary objects
create database if not exists tm_db_lab;
create table if not exists tm_db_lab.public.tb_credit_card
( name varchar(500)
 ,credit_card_name variant
 ,credit_card_number variant
);


-- Let's insert a row with sensitive data (credit card name and number)
truncate table tm_db_lab.public.tb_credit_card;
insert into tm_db_lab.public.tb_credit_card 
with fake_keys as (
  select 
       to_binary(sha2('myScret', 256)) as encryption_key
      ,to_binary(substr(to_binary(hex_encode('everyThingMoreThan86'), 'hex'), 0, 12)) as initialization_vector
      ,to_binary(hex_encode('additional_authenticated_data')) as aad_column
  )
   select 
    'George' as name
    ,encrypt_raw(
         to_binary(hex_encode('George Washington'), 'HEX') --data target
        ,encryption_key --encryption_key
        ,initialization_vector --initialization_vector
        ,aad_column -- aad_column
        ,'AES-GCM') as credit_card_name
     ,encrypt_raw(
           to_binary(hex_encode(6866016841861064088), 'HEX') --data target
,encryption_key --encryption_key
          ,initialization_vector --initialization_vector
          ,aad_column -- aad_column
          ,'AES-GCM') as credit_card_number
  from fake_keys;
select * from tm_db_lab.public.tb_credit_card;


/*
  Decrypting you data
  Let's suppose that you need to shit this table with another, so maybe you will need to decrypt this data.
*/
select
  name
  ,hex_decode_string(to_varchar(decrypt_raw(
              as_binary(get(credit_card_name, 'ciphertext'))
              ,to_binary('88327c5fe63fb2439c17e733e6aa2437bdb8aa24904f32775dfac12996db7cee') -- encryption_key
              ,as_binary(get(credit_card_name, 'iv'))
              ,to_binary('6164646974696F6E616C5F61757468656E746963617465645F64617461') -- aad_column
              ,'AES-GCM'
              ,as_binary(get(credit_card_name, 'tag'))
            ))) as credit_card_name
    ,hex_decode_string(to_varchar(decrypt_raw(
                  as_binary(get(credit_card_number, 'ciphertext'))
                  ,to_binary('88327c5fe63fb2439c17e733e6aa2437bdb8aa24904f32775dfac12996db7cee') -- encryption_key
                  ,as_binary(get(credit_card_number, 'iv'))
                  ,to_binary('6164646974696F6E616C5F61757468656E746963617465645F64617461') -- aad_column
                  ,'AES-GCM'
                  ,as_binary(get(credit_card_number, 'tag'))
                ))) as credit_card_number            
from tm_db_lab.public.tb_credit_card;


--Really Simples mask and weak approach
select  hex_encode('George Washington')


-- Encoding and encryption
select 
 encrypt_raw(
    to_binary(hex_encode('Hellow world'), 'HEX') -- data target
   ,to_binary('88327c5fe63fb2439c17e733e6aa2437bdb8aa24904f32775dfac12996db7cee') -- encryption_key
   ,to_binary('65766572795468696E674D6F') -- initialization_vector
   ,to_binary('6164646974696F6E616C5F61757468656E746963617465645F64617461') -- aad_column
   ,'AES-GCM'
 ) as col_encrypted;
