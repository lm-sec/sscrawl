FROM hashicorp/vault:latest

ADD data /vault/file/data
RUN chmod -R 777 /vault/file/data
ADD config.hcl /vault/config/

ADD unseal.sh /
RUN chmod 777 /unseal.sh

EXPOSE 8200

CMD ["./unseal.sh"]