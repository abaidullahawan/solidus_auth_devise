# frozen_string_literal: true

module Spree
  class User < Spree::Base
    include UserMethods
    attr_accessor :login
    has_one_attached :profile

    devise :database_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :validatable, :encryptable, :confirmable, :timeoutable, :lockable,
           :omniauthable, omniauth_providers: [:google_oauth2, :facebook]
    devise :confirmable if Spree::Auth::Config[:confirmable]
    EMAIL_REGEX = /\A[A-Za-z0-9._%]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\z/
    validates :email, presence: false, allow_nil: true, uniqueness: { case_insensitive: false }, if: -> { email.present? }, format: { with: EMAIL_REGEX }
    validates :phone_number, presence: false, allow_nil: true, uniqueness: true
    validate :email_or_phone_number_present
    validates :password, length: { minimum: 8 }, on: :create
    validate :password_complexity, on: :create

    def email_required?
      false
    end

    def exceeded_login_attempts?
      failed_attempts >= 5 && last_login_attempt_at.to_i >= 1.hour.ago.to_i
    end

    def email_or_phone_number_present
      return if email.present? || phone_number.present?

      errors.add(:email, 'Email or Phone Number must be exist.')
      errors.add(:phone_number, 'Email or Phone Number must be exist.')
    end

    if defined?(Spree::SoftDeletable)
      include Spree::SoftDeletable
    else
      acts_as_paranoid
      include Spree::ParanoiaDeprecations

      include Discard::Model
      self.discard_column = :deleted_at
    end

    after_destroy :scramble_email_and_password
    after_discard :scramble_email_and_password

    def password=(new_password)
      generate_spree_api_key if new_password.present? && spree_api_key.present?
      super
    end

    # before_validation :set_login

    scope :admin, -> { includes(:spree_roles).where("#{Role.table_name}.name" => "admin") }

    def self.admin_created?
      User.admin.count > 0
    end

    def admin?
      has_spree_role?('admin')
    end

    def guest?
      has_spree_role?('guest')
    end

    def confirmed?
      !!confirmed_at
    end

    def self.from_omniauth(auth)
      existing_user = find_by(email: auth.info.email)

      if existing_user
        existing_user.update(provider: auth.provider, uid: auth.uid)
        existing_user
      else
        lowercase_letter = ('a'..'z').to_a.sample
        uppercase_letter = ('A'..'Z').to_a.sample
        digit = ('0'..'9').to_a.sample
        special_character = ['!', '@', '#', '$', '%', '^', '&', '*'].sample

        all_characters = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + ['!', '@', '#', '$', '%', '^', '&', '*']
        remaining_characters = all_characters - [lowercase_letter, uppercase_letter, digit, special_character]
        additional_characters = remaining_characters.sample(16)

        password_array = [lowercase_letter, uppercase_letter, digit, special_character] + additional_characters
        generate_random_password = password_array.shuffle.join

        where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
          user.email = auth.info.email
          user.password = generate_random_password
          user.skip_confirmation!
        end
      end
    end

    protected

    def password_required?
      !persisted? || password.present? || password_confirmation.present?
    end

    private

    def password_complexity
      return if password.blank?

      unless password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#\$%\^&\*])/)
        errors.add :password, 'must include at least one lowercase letter, one uppercase letter, one digit, and one special character'
      end
    end

    def self.find_for_database_authentication(conditions = {})
      login_param = conditions[:login].downcase
      find_by('lower(email) = ? OR phone_number = ?', login_param, login_param)
    end

    def login=(login)
      @login = self.email || self.phone_number
    end
  
    def set_login
      @login || self.phone_number || self.email
    end

    def scramble_email_and_password
      return true if destroyed?

      self.email = SecureRandom.uuid + "@example.net"
      self.login = email || phone_number
      self.password = SecureRandom.hex(8)
      self.password_confirmation = password
      save
    end
  end
end
